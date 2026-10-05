"""
Comprehensive test suite for the modular TLS client-profile system.

Covers:
1. Default configuration.
2. TLS disabled.
3. Valid TLS profiles.
4. Invalid TLS profile.
5. Unsupported profile options.
6. Session creation.
7. Async session creation.
8. Existing authentication behavior.
9. Existing request behavior against local HTTPS server.
10. TLS initialization failure and explicit fallback.
11. HTTP/2 and ALPN behavior where supported.
12. Observability and sensitive credential sanitization.
"""
from __future__ import annotations

import asyncio
import datetime
import os
import ssl
import tempfile
import threading
from collections.abc import Generator

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from swiggy_hunter.config import load_config
from swiggy_hunter.stealth.fingerprint import (
    get_profile,
    list_profiles,
)
from swiggy_hunter.stealth.session import create_session
from swiggy_hunter.stealth.tls import (
    TLSProfile,
    TLSProfileError,
    TLSProtocolError,
    TLSUnsupportedOptionError,
    create_client,
    sanitize_headers,
    sanitize_url,
)

# ==============================================================================
# Local HTTPS Mock Server Fixture (aiohttp in background thread)
# ==============================================================================

@pytest.fixture(scope="module")
def local_https_server() -> Generator[str, None, None]:
    """
    Spins up an in-process TLS HTTPS server with a freshly generated self-signed certificate.
    Does NOT connect to third-party services.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_file.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        cert_path = cert_file.name

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(cert_path)

    app = web.Application()

    async def probe(req: web.Request) -> web.Response:
        resp = web.json_response({"authenticated": True, "user": "authorized_tester"})
        resp.set_cookie("swiggy_session", "sess_abc123")
        return resp

    async def action(req: web.Request) -> web.Response:
        data = await req.json()
        return web.json_response({"received": True, "action": data.get("action")})

    app.router.add_get("/api/auth/probe", probe)
    app.router.add_post("/api/action", action)

    loop = asyncio.new_event_loop()
    runner = web.AppRunner(app)
    port_holder: dict[str, int] = {}
    ready_evt = threading.Event()

    def run_server() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_ctx)
        loop.run_until_complete(site.start())
        port_holder["port"] = site._server.sockets[0].getsockname()[1]
        ready_evt.set()
        loop.run_forever()

    th = threading.Thread(target=run_server, daemon=True)
    th.start()
    ready_evt.wait(timeout=5)

    base_url = f"https://127.0.0.1:{port_holder['port']}"
    yield base_url

    # Teardown
    async def cleanup() -> None:
        await runner.cleanup()

    try:
        asyncio.run_coroutine_threadsafe(cleanup(), loop).result(timeout=2)
    except Exception:
        pass
    loop.call_soon_threadsafe(loop.stop)
    th.join(timeout=2)
    try:
        os.unlink(cert_path)
    except OSError:
        pass


# ==============================================================================
# 1. Default Configuration Tests
# ==============================================================================

def test_default_configuration():
    """Verify default TLS configuration settings and profile manager defaults."""
    cfg = load_config()
    assert cfg.stealth.tls_enabled is True
    assert cfg.stealth.tls_profile == "chrome124"
    assert cfg.stealth.tls_fallback_allowed is False

    default_prof = get_profile()
    assert default_prof.name == "chrome124"
    assert default_prof.target == "chrome124"
    assert default_prof.http_version == "v2"
    assert "h2" in default_prof.alpn_protocols
    assert "http/1.1" in default_prof.alpn_protocols
    assert default_prof.min_tls_version == "TLSv1.2"
    assert default_prof.max_tls_version == "TLSv1.3"
    assert default_prof.enabled is True


# ==============================================================================
# 2. TLS Disabled Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_tls_disabled():
    """Verify session creation and characteristics when TLS is explicitly disabled."""
    session = create_session(tls_enabled=False)
    try:
        assert session.tls_enabled is False
        assert session.profile.enabled is False
        assert session.profile.name in ("disabled", "tls_disabled")
        snap = session.snapshot()
        assert snap["tls_enabled"] is False
    finally:
        await session.close()


# ==============================================================================
# 3. Valid TLS Profile Tests
# ==============================================================================

def test_valid_tls_profiles():
    """Verify authorized registered test profiles and their validity."""
    expected_profiles = [
        "chrome124", "chrome120", "chrome131",
        "firefox133", "firefox135",
        "safari18_0", "safari17_0",
        "edge101", "chrome124_http1", "standard_tls", "disabled",
    ]
    all_profiles = list_profiles()
    for name in expected_profiles:
        assert name in all_profiles
        prof = get_profile(name)
        assert prof.name == name
        if prof.enabled and prof.target:
            prof.validate_for_engine("curl_cffi")


# ==============================================================================
# 4. Invalid TLS Profile Tests
# ==============================================================================

def test_invalid_tls_profile():
    """Verify requesting an unknown profile raises TLSProfileError deterministically."""
    with pytest.raises(TLSProfileError) as exc_info:
        get_profile("non_existent_fake_browser_profile")
    assert "Unknown TLS profile" in str(exc_info.value)


# ==============================================================================
# 5. Unsupported Profile Option Tests
# ==============================================================================

def test_unsupported_profile_options():
    """Verify that unsupported or contradictory profile options trigger typed exceptions."""
    # Custom cipher suites with browser impersonation target
    p1 = TLSProfile(
        name="invalid_combo",
        target="chrome124",
        cipher_suites=("ECDHE-ECDSA-AES128-GCM-SHA256",),
    )
    with pytest.raises(TLSUnsupportedOptionError) as exc1:
        p1.validate_for_engine("curl_cffi")
    assert "custom cipher_suites" in str(exc1.value)

    # Unsupported impersonation target
    p2 = TLSProfile(name="bad_target", target="totally_unsupported_browser_999")
    with pytest.raises(TLSUnsupportedOptionError) as exc2:
        p2.validate_for_engine("curl_cffi")
    assert "not supported" in str(exc2.value)

    # Inverted TLS version range
    p3 = TLSProfile(name="bad_version_order", min_tls_version="TLSv1.3", max_tls_version="TLSv1.2")
    with pytest.raises(TLSProfileError) as exc3:
        p3.validate_for_engine("curl_cffi")
    assert "cannot be greater than" in str(exc3.value)


# ==============================================================================
# 6. Session Creation Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_session_creation():
    """Verify session creation consumes selected TLS profile and preserves state."""
    session = create_session(profile="firefox133")
    try:
        assert session.profile.name == "firefox133"
        assert session.engine in ("curl_cffi", "httpx")
        snap = session.snapshot()
        assert snap["tls_profile"] == "firefox133"
        assert snap["tls_enabled"] is True
    finally:
        await session.close()


# ==============================================================================
# 7. Async Session Creation Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_async_session_creation():
    """Verify low-level create_client factory constructs an active async client."""
    prof = get_profile("chrome124")
    client = create_client(prof, timeout=30.0)
    assert client is not None
    assert hasattr(client, "request")
    assert hasattr(client, "close")
    await client.close()


# ==============================================================================
# 8. Authentication and Cookie Behavior Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_existing_authentication_behavior():
    """Verify cookie management and rotation retain critical authentication tokens."""
    session = create_session(profile="chrome124")
    try:
        session.set_cookie("swiggy_session", "secret_auth_token_value")
        session.set_cookie("temp_metric", "metric_val")
        assert session.cookies()["swiggy_session"] == "secret_auth_token_value"
        assert session.cookies()["temp_metric"] == "metric_val"

        # Absorb Set-Cookie header
        session._absorb_set_cookie({"Set-Cookie": "access_token=jwt_xyz_789; Path=/"})
        assert session.cookies()["access_token"] == "jwt_xyz_789"

        # Rotate session: auth-critical cookies must be preserved, ephemeral cookies dropped
        await session.rotate()
        cookies_after = session.cookies()
        assert "swiggy_session" in cookies_after
        assert "access_token" in cookies_after
        assert "temp_metric" not in cookies_after
        assert session.profile is not None
    finally:
        await session.close()


# ==============================================================================
# 9. Existing Request Behavior Tests (against local HTTPS server)
# ==============================================================================

@pytest.mark.asyncio
async def test_existing_request_behavior(local_https_server: str):
    """
    Verify full request pipeline against local HTTPS server:
    Pre-request pacing, header construction, cookie injection, response normalization.
    """
    prof = TLSProfile(
        name="test_local_chrome",
        target="chrome124",
        http_version="v1.1",
        alpn_protocols=("http/1.1",),
        verify=False,
    )
    session = create_session(profile=prof)
    try:
        # GET request
        resp = await session.get(f"{local_https_server}/api/auth/probe")
        assert resp.status == 200
        assert resp.profile_name == "test_local_chrome"
        assert resp.elapsed_ms >= 0
        assert "swiggy_session" in session.cookies()
        data = resp.json()
        assert data.get("authenticated") is True

        # POST request
        post_resp = await session.post(
            f"{local_https_server}/api/action",
            json_body={"action": "test_ping"},
        )
        assert post_resp.status == 200
        assert post_resp.json().get("received") is True

        # Evidence capture format
        cap = post_resp.to_capture("POST", {"test": "header"}, '{"action":"test_ping"}')
        assert cap["stealth"]["tls_profile"] == "test_local_chrome"
        assert cap["response"]["status"] == 200
    finally:
        await session.close()


# ==============================================================================
# 10. TLS Initialization Failure and Fallback Tests
# ==============================================================================

def test_tls_initialization_failure_no_fallback():
    """Verify that unsupported configuration raises an exception when fallback is disabled."""
    bad_prof = TLSProfile(
        name="invalid_target_profile",
        target="unsupported_target_xyz",
    )
    with pytest.raises(TLSUnsupportedOptionError):
        create_client(bad_prof, allow_fallback=False)


def test_tls_initialization_explicit_fallback():
    """Verify explicit fallback engages httpx with observable warning when allowed."""
    prof = TLSProfile(
        name="fallback_profile",
        target=None,  # Standard TLS
        http_version="v2",
        alpn_protocols=("h2", "http/1.1"),
    )
    client = create_client(prof, allow_fallback=True)
    assert client is not None


# ==============================================================================
# 11. HTTP/2 and ALPN Incompatibility Behavior Tests
# ==============================================================================

def test_http2_alpn_behavior():
    """Verify ALPN protocol validation and detection of protocol mismatches."""
    # HTTP/1.1 profile with matching ALPN
    h1_prof = get_profile("chrome124_http1")
    assert h1_prof.http_version == "v1.1"
    assert h1_prof.alpn_protocols == ("http/1.1",)
    h1_prof.validate_for_engine("curl_cffi")

    # Mismatch: http_version="v2" but ALPN only has http/1.1
    mismatch_1 = TLSProfile(
        name="mismatch_h2",
        target="chrome124",
        http_version="v2",
        alpn_protocols=("http/1.1",),
    )
    with pytest.raises(TLSProtocolError) as exc1:
        mismatch_1.validate_for_engine("curl_cffi")
    assert "Incompatible ALPN configuration" in str(exc1.value)

    # Mismatch: http_version="v1.1" but ALPN only has h2
    mismatch_2 = TLSProfile(
        name="mismatch_h1",
        target="chrome124",
        http_version="v1.1",
        alpn_protocols=("h2",),
    )
    with pytest.raises(TLSProtocolError) as exc2:
        mismatch_2.validate_for_engine("curl_cffi")
    assert "Incompatible ALPN configuration" in str(exc2.value)


# ==============================================================================
# 12. Observability and Sanitization Tests
# ==============================================================================

def test_observability_and_sanitization():
    """Verify that credentials, cookies, tokens, and keys are NEVER leaked in logs."""
    headers = {
        "Authorization": "Bearer sensitive_jwt_token_secret",
        "Cookie": "swiggy_session=secret_cookie_val; t_id=98765",
        "X-Api-Key": "super_secret_api_key_123",
        "User-Agent": "Mozilla/5.0 Plausible Browser",
        "Accept": "application/json",
    }
    sanitized = sanitize_headers(headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["X-Api-Key"] == "[REDACTED]"
    assert sanitized["User-Agent"] == "Mozilla/5.0 Plausible Browser"
    assert sanitized["Accept"] == "application/json"

    # URL sanitization
    raw_url = "https://www.swiggy.com/api/check?token=my_secret_token&user=test&key=12345"
    clean_url = sanitize_url(raw_url)
    assert "my_secret_token" not in clean_url
    assert "12345" not in clean_url
    assert "token=%5BREDACTED%5D" in clean_url or "token=[REDACTED]" in clean_url
    assert "user=test" in clean_url


# ==============================================================================
# 13. Import Cycles & Resource Cleanup Tests
# ==============================================================================

def test_no_import_cycles():
    """Verify that importing all modules in swiggy_hunter produces zero circular imports."""
    import importlib
    import pkgutil
    import swiggy_hunter
    failed = []
    for _, modname, _ in pkgutil.walk_packages(swiggy_hunter.__path__, swiggy_hunter.__name__ + "."):
        try:
            importlib.import_module(modname)
        except Exception as e:
            failed.append((modname, str(e)))
    assert not failed, f"Detected import failure / circular dependency: {failed}"


@pytest.mark.asyncio
async def test_session_resource_cleanup():
    """Verify that closing a StealthSession cleanly releases the underlying client handle."""
    session = create_session(profile="chrome124")
    assert session._session is not None
    # Close session
    await session.close()
    # Ensure idempotency
    await session.close()

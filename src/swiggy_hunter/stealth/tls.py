"""
stealth/tls.py — Modular TLS client factory and abstraction layer.

Separation of responsibilities:
  main.py -> config.py -> fingerprint/profile manager -> stealth/tls.py -> session.py -> HTTP client

Responsibilities:
  - Construct and configure TLS-capable HTTP clients (curl_cffi AsyncSession preferred,
    httpx.AsyncClient optional explicit fallback).
  - Define typed TLS exceptions for structured error handling.
  - Define the TLSProfile configuration dataclass representing TLS and protocol settings.
  - Enforce strict validation of unsupported TLS options and protocol combinations.
  - Implement safe diagnostic logging without leaking credentials, cookies, or secrets.
"""
from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..logging_setup import get_logger

log = get_logger(__name__)


# ==============================================================================
# Typed Exceptions
# ==============================================================================

class TLSError(Exception):
    """Base exception for all TLS-related errors."""


class TLSProfileError(TLSError):
    """Raised when a TLS profile is invalid, unrecognized, or contains conflicting settings."""


class TLSUnsupportedOptionError(TLSProfileError):
    """Raised when an option is requested that the underlying TLS engine cannot support."""


class TLSInitializationError(TLSError):
    """Raised when the underlying TLS client or SSL context fails to initialize."""


class TLSVerificationError(TLSError):
    """Raised when certificate verification or TLS trust evaluation fails."""


class TLSConnectionError(TLSError):
    """Raised when a network-level TLS connection or handshake fails."""


class TLSProtocolError(TLSError):
    """Raised on ALPN or HTTP protocol mismatch or negotiation failure."""


# ==============================================================================
# Engine Discovery and Target Capabilities
# ==============================================================================

_KNOWN_CURL_TARGETS = {
    "edge99", "edge101", "chrome99", "chrome100", "chrome101", "chrome104",
    "chrome107", "chrome110", "chrome116", "chrome119", "chrome120",
    "chrome123", "chrome124", "chrome131", "chrome133a", "chrome136",
    "chrome142", "chrome145", "chrome146", "chrome150", "chrome99_android",
    "chrome131_android", "safari153", "safari155", "safari170",
    "safari172_ios", "safari180", "safari180_ios", "safari184",
    "safari184_ios", "safari260", "safari260_ios", "safari2601",
    "firefox133", "firefox135", "firefox144", "firefox147", "tor145",
    "safari15_3", "safari15_5", "safari17_0", "safari17_2_ios",
    "safari18_0", "safari18_0_ios",
}

_TLS_VERSION_RANK = {
    "TLSv1.0": 1,
    "TLSv1.1": 2,
    "TLSv1.2": 3,
    "TLSv1.3": 4,
}

SENSITIVE_PARAM_PATTERN = re.compile(
    r"(token|key|secret|password|passwd|auth|bearer|signature|session|cookie|otp)",
    re.IGNORECASE,
)

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "token",
    "x-access-token",
    "x-auth-token",
    "session",
    "proxy-authorization",
    "secret",
}


def get_supported_curl_targets() -> set[str]:
    """Return the set of impersonate targets supported by the installed curl_cffi package."""
    try:
        from curl_cffi.requests import BrowserType  # type: ignore
        return {e.value for e in BrowserType}
    except Exception:
        return set(_KNOWN_CURL_TARGETS)


def _try_curl_cffi() -> Any | None:
    try:
        from curl_cffi.requests import AsyncSession  # type: ignore
        return AsyncSession
    except Exception:
        return None


def _try_httpx() -> Any | None:
    try:
        import httpx  # type: ignore
        return httpx.AsyncClient
    except Exception:
        return None


def engine_name() -> str:
    """Return the active primary HTTP/TLS engine name ('curl_cffi', 'httpx', or 'none')."""
    if _try_curl_cffi() is not None:
        return "curl_cffi"
    if _try_httpx() is not None:
        return "httpx"
    return "none"


# ==============================================================================
# Observability and Sanitization Helpers
# ==============================================================================

def sanitize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """
    Sanitize headers by redacting sensitive authentication tokens, cookies,
    and credentials before logging.
    """
    if not headers:
        return {}
    sanitized: dict[str, str] = {}
    for k, v in headers.items():
        key_str = str(k).lower()
        if (
            key_str in SENSITIVE_HEADER_KEYS
            or any(s in key_str for s in ("token", "secret", "auth", "cookie", "password"))
        ):
            sanitized[str(k)] = "[REDACTED]"
        else:
            sanitized[str(k)] = str(v)
    return sanitized


def sanitize_url(url: str) -> str:
    """
    Sanitize a URL by masking sensitive query parameter values before logging.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        cleaned_pairs = []
        for k, v in pairs:
            if SENSITIVE_PARAM_PATTERN.search(k):
                cleaned_pairs.append((k, "[REDACTED]"))
            else:
                cleaned_pairs.append((k, v))
        new_query = urlencode(cleaned_pairs)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))
    except Exception:
        return "[UNPARSEABLE_URL]"


# ==============================================================================
# TLS Profile Abstraction
# ==============================================================================

@dataclass(frozen=True)
class TLSProfile:
    """
    Configuration representation of a client TLS profile and protocol settings.

    A TLS profile represents configuration, not application logic.
    Keep profile selection separate from session creation.
    """
    name: str
    target: str | None = None
    http_version: str = "v2"                         # "v1.1", "v2", "auto"
    alpn_protocols: tuple[str, ...] = ("h2", "http/1.1")
    min_tls_version: str = "TLSv1.2"                 # "TLSv1.2", "TLSv1.3"
    max_tls_version: str = "TLSv1.3"
    cipher_suites: tuple[str, ...] | None = None     # Custom ciphers for standard TLS
    verify: bool | str = True                        # True, False, or path to CA bundle
    cert: str | tuple[str, str] | None = None        # Client cert
    enabled: bool = True                             # False = unencrypted / plain HTTP
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate_for_engine(self, engine: str) -> None:
        """
        Validate profile configuration against the target engine's capabilities.
        Raises typed exceptions if options are incompatible or unsupported.
        """
        # 1. Validate version range
        min_rank = _TLS_VERSION_RANK.get(self.min_tls_version)
        max_rank = _TLS_VERSION_RANK.get(self.max_tls_version)
        if min_rank is None:
            raise TLSProfileError(
                f"Unknown min_tls_version '{self.min_tls_version}'. "
                f"Allowed: {list(_TLS_VERSION_RANK.keys())}"
            )
        if max_rank is None:
            raise TLSProfileError(
                f"Unknown max_tls_version '{self.max_tls_version}'. "
                f"Allowed: {list(_TLS_VERSION_RANK.keys())}"
            )
        if min_rank > max_rank:
            raise TLSProfileError(
                f"Invalid TLS version range: min_tls_version '{self.min_tls_version}' "
                f"cannot be greater than max_tls_version '{self.max_tls_version}'"
            )

        # 2. Validate ALPN vs HTTP protocol
        if self.http_version in ("v1.0", "v1.1") and "http/1.1" not in self.alpn_protocols:
            raise TLSProtocolError(
                f"Incompatible ALPN configuration for profile '{self.name}': "
                f"http_version is '{self.http_version}', but ALPN protocols {self.alpn_protocols} "
                "do not include 'http/1.1'."
            )
        if self.http_version in ("v2", "http2") and "h2" not in self.alpn_protocols:
            raise TLSProtocolError(
                f"Incompatible ALPN configuration for profile '{self.name}': "
                f"http_version is '{self.http_version}', but ALPN protocols {self.alpn_protocols} "
                "do not include 'h2'."
            )

        # 3. Engine-specific validations
        if engine == "curl_cffi":
            if self.target is not None:
                supported = get_supported_curl_targets()
                if self.target not in supported:
                    raise TLSUnsupportedOptionError(
                        f"Target '{self.target}' in profile '{self.name}' is not supported by "
                        f"installed curl_cffi. Available targets: {sorted(supported)}"
                    )
                if self.cipher_suites is not None:
                    raise TLSUnsupportedOptionError(
                        f"Profile '{self.name}' specifies custom cipher_suites while impersonating "
                        f"'{self.target}'. curl_cffi's libcurl-impersonate hardcodes the complete "
                        "ClientHello cipher suite and extension list to mirror the browser. "
                        "Custom cipher suites cannot be mixed with browser impersonation targets."
                    )
        elif engine == "httpx" and self.target is not None:
            raise TLSUnsupportedOptionError(
                f"Engine 'httpx' does not support browser ClientHello impersonation target "
                f"'{self.target}'. httpx relies on Python's standard OpenSSL wrapper and cannot "
                "reproduce browser GREASE or extension permutations."
            )


# ==============================================================================
# Client Session Factory
# ==============================================================================

def create_client(
    profile: TLSProfile,
    timeout: float = 45.0,
    proxy: str | None = None,
    allow_fallback: bool = False,
) -> Any:
    """
    Construct and configure a TLS-capable HTTP client for the given profile.

    Separation of concerns:
      Consumes a pre-validated TLSProfile. Does not mutate global state.
      Never silently falls back to a different TLS stack unless explicitly authorized
      via `allow_fallback=True`.
    """
    active_engine = engine_name()
    if active_engine == "none":
        raise TLSInitializationError(
            "No HTTP client library is available. Install curl-cffi or httpx[http2]."
        )

    # Validate against active primary engine
    if active_engine == "curl_cffi":
        try:
            profile.validate_for_engine("curl_cffi")
        except TLSUnsupportedOptionError as e:
            if not allow_fallback:
                raise
            log.warning(
                "tls.unsupported_option_fallback_check",
                profile=profile.name,
                error=str(e),
                allow_fallback=allow_fallback,
            )

        AsyncSession = _try_curl_cffi()
        if AsyncSession is not None:
            try:
                # Map HTTP version to CurlHttpVersion enum/int (curl_cffi requires integer or enum)
                http_ver: Any = None
                try:
                    from curl_cffi.requests.session import CurlHttpVersion  # type: ignore
                    if profile.http_version in ("v1.0", "v1.1"):
                        http_ver = CurlHttpVersion.V1_1
                    elif profile.http_version in ("v2", "http2"):
                        http_ver = CurlHttpVersion.V2_0
                    elif profile.http_version in ("v3", "http3"):
                        http_ver = CurlHttpVersion.V3
                except Exception:
                    if profile.http_version in ("v1.0", "v1.1"):
                        http_ver = 2
                    elif profile.http_version in ("v2", "http2"):
                        http_ver = 3

                # Verify and cert handling
                verify_arg = profile.verify
                cert_arg = profile.cert

                kwargs: dict[str, Any] = {
                    "timeout": timeout,
                    "allow_redirects": True,
                    "verify": verify_arg,
                }
                if proxy:
                    kwargs["proxy"] = proxy
                if cert_arg:
                    kwargs["cert"] = cert_arg

                if not profile.enabled:
                    # TLS disabled / unencrypted plain mode
                    session = AsyncSession(impersonate=None, http_version=http_ver, **kwargs)
                else:
                    session = AsyncSession(
                        impersonate=profile.target,
                        http_version=http_ver,
                        **kwargs,
                    )

                log.info(
                    "tls.client_initialized",
                    engine="curl_cffi",
                    profile=profile.name,
                    target=profile.target,
                    http_version=profile.http_version,
                    alpn=list(profile.alpn_protocols),
                )
                return session
            except Exception as exc:
                log.exception("tls.curl_cffi_init_failed", profile=profile.name)
                if not allow_fallback:
                    raise TLSInitializationError(
                        f"Failed to initialize curl_cffi session for profile '{profile.name}': {exc}"
                    ) from exc

    # Fallback to httpx if allowed
    if allow_fallback or active_engine == "httpx":
        AsyncClient = _try_httpx()
        if AsyncClient is not None:
            try:
                profile.validate_for_engine("httpx")
            except TLSUnsupportedOptionError as e:
                # When falling back from browser impersonation, make it observable!
                log.warning(
                    "tls.fallback_engaged",
                    profile=profile.name,
                    target=profile.target,
                    fallback_engine="httpx",
                    reason=str(e),
                    notice="Browser ClientHello impersonation is not reproduced in httpx fallback",
                )

            use_http2 = (
                profile.http_version in ("v2", "http2", "auto")
                and "h2" in profile.alpn_protocols
            )

            # Build SSLContext for httpx if TLS is enabled
            ssl_ctx: Any = True
            if profile.enabled:
                try:
                    ssl_ctx = ssl.create_default_context()
                    if profile.min_tls_version == "TLSv1.3":
                        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    elif profile.min_tls_version == "TLSv1.2":
                        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

                    if profile.max_tls_version == "TLSv1.2":
                        ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                    elif profile.max_tls_version == "TLSv1.3":
                        ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3

                    if profile.cipher_suites:
                        ssl_ctx.set_ciphers(":".join(profile.cipher_suites))

                    if profile.verify is False:
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE
                    elif isinstance(profile.verify, str):
                        ssl_ctx.load_verify_locations(cafile=profile.verify)

                    if profile.alpn_protocols:
                        try:
                            ssl_ctx.set_alpn_protocols(list(profile.alpn_protocols))
                        except (NotImplementedError, ssl.SSLError):
                            pass
                except Exception as ctx_err:
                    log.exception("tls.httpx_ssl_context_failed", error=str(ctx_err))
                    if not allow_fallback:
                        raise TLSInitializationError(
                            f"Failed to configure SSL context for httpx: {ctx_err}"
                        ) from ctx_err

            for try_h2 in (use_http2, False):
                try:
                    client_kwargs: dict[str, Any] = {
                        "timeout": timeout,
                        "follow_redirects": True,
                        "http2": try_h2,
                        "headers": {},
                    }
                    if proxy:
                        client_kwargs["proxy"] = proxy
                    if profile.cert:
                        client_kwargs["cert"] = profile.cert
                    if profile.enabled:
                        client_kwargs["verify"] = ssl_ctx
                    else:
                        client_kwargs["verify"] = False

                    session = AsyncClient(**client_kwargs)
                    log.warning(
                        "tls.httpx_client_ready",
                        profile=profile.name,
                        http2=try_h2,
                        target=profile.target,
                    )
                    return session
                except Exception as h2_err:
                    if not try_h2:
                        raise TLSInitializationError(
                            f"httpx client initialization failed: {h2_err}"
                        ) from h2_err

    raise TLSInitializationError(
        f"Unable to initialize TLS client for profile '{profile.name}'. "
        "No suitable HTTP engine initialized successfully."
    )


def make_curl_session(
    impersonate: str = "chrome124",
    timeout: float = 45.0,
    profile: TLSProfile | None = None,
    allow_fallback: bool = False,
) -> Any:
    """
    Backward-compatible factory function.
    Exposes existing API while consuming the modular TLSProfile system.
    """
    if profile is None:
        target = impersonate if impersonate in get_supported_curl_targets() else "chrome124"
        profile = TLSProfile(
            name=impersonate,
            target=target,
            http_version="v2",
            alpn_protocols=("h2", "http/1.1"),
        )
    return create_client(profile, timeout=timeout, allow_fallback=allow_fallback)

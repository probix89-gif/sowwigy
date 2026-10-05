"""
Fingerprint — everything a real browser sends that hints at identity.

One Fingerprint = one coherent bundle:
  - User-Agent
  - Sec-CH-UA family (client hints)
  - Accept-Language / Accept-Encoding
  - viewport
  - timezone
  - platform / mobile flag
  - TLS impersonation target for curl_cffi
  - optional extra headers

ProfileManager:
  Maintains authorized test profiles, enforces deterministic selection,
  validates requested profile names, and maps fingerprints to TLS profiles.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from ..logging_setup import get_logger
from .tls import (
    TLSProfile,
    TLSProfileError,
    get_supported_curl_targets,
)

log = get_logger(__name__)

DEFAULT_PROFILE_NAME = "chrome124"


# ==============================================================================
# Fingerprint Dataclass
# ==============================================================================

@dataclass(frozen=True)
class Fingerprint:
    id: str
    ua: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    accept_language: str
    accept_encoding: str
    tls_impersonate: str          # curl_cffi target, e.g. "chrome124"
    platform: str                 # "Windows" | "macOS" | "Linux" | "Android" | "iOS"
    mobile: bool = False
    viewport: tuple[int, int] = (1366, 800)
    timezone: str = "Asia/Kolkata"
    extra_headers: dict[str, str] = field(default_factory=dict)

    def to_headers(self) -> dict[str, str]:
        h = {
            "user-agent": self.ua,
            "accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "accept-language": self.accept_language,
            "accept-encoding": self.accept_encoding,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": self.sec_ch_ua_mobile,
            "sec-ch-ua-platform": self.sec_ch_ua_platform,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0",
            "connection": "keep-alive",
        }
        h.update(self.extra_headers)
        return h

    def signature(self) -> str:
        raw = f"{self.ua}|{self.sec_ch_ua}|{self.accept_language}|{self.tls_impersonate}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ==============================================================================
# TLS Profile Manager
# ==============================================================================

class ProfileManager:
    """
    Profile Manager responsible for maintaining authorized test profiles,
    enforcing deterministic profile selection, and validating profile configurations.
    """

    def __init__(self, initial_profiles: list[TLSProfile] | None = None) -> None:
        self._profiles: dict[str, TLSProfile] = {}
        defaults = initial_profiles if initial_profiles is not None else self._build_default_profiles()
        for p in defaults:
            self._profiles[p.name] = p

    @staticmethod
    def _build_default_profiles() -> list[TLSProfile]:
        """Authorized test profiles supported by the networking stack."""
        return [
            # Chrome Profiles
            TLSProfile(
                name="chrome124",
                target="chrome124",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Chrome", "version": 124, "platform": "desktop"},
            ),
            TLSProfile(
                name="chrome120",
                target="chrome120",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Chrome", "version": 120, "platform": "desktop"},
            ),
            TLSProfile(
                name="chrome131",
                target="chrome131",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Chrome", "version": 131, "platform": "desktop"},
            ),
            # Firefox Profiles
            TLSProfile(
                name="firefox133",
                target="firefox133",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Firefox", "version": 133, "platform": "desktop"},
            ),
            TLSProfile(
                name="firefox135",
                target="firefox135",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Firefox", "version": 135, "platform": "desktop"},
            ),
            # Safari Profiles
            TLSProfile(
                name="safari18_0",
                target="safari18_0",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Safari", "version": 18, "platform": "macOS"},
            ),
            TLSProfile(
                name="safari17_0",
                target="safari17_0",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Safari", "version": 17, "platform": "macOS"},
            ),
            # Edge Profile
            TLSProfile(
                name="edge101",
                target="edge101",
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Edge", "version": 101, "platform": "desktop"},
            ),
            # Protocol-Specific Profiles
            TLSProfile(
                name="chrome124_http1",
                target="chrome124",
                http_version="v1.1",
                alpn_protocols=("http/1.1",),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"browser": "Chrome", "protocol": "http/1.1"},
            ),
            TLSProfile(
                name="http1_only",
                target="chrome124",
                http_version="v1.1",
                alpn_protocols=("http/1.1",),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"protocol": "http/1.1_only"},
            ),
            # Standard TLS (no browser ClientHello impersonation)
            TLSProfile(
                name="standard_tls",
                target=None,
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
                metadata={"type": "standard_openssl"},
            ),
            # TLS Disabled (Plain unencrypted HTTP)
            TLSProfile(
                name="disabled",
                target=None,
                http_version="v1.1",
                alpn_protocols=("http/1.1",),
                enabled=False,
                verify=False,
                metadata={"type": "tls_disabled"},
            ),
            TLSProfile(
                name="tls_disabled",
                target=None,
                http_version="v1.1",
                alpn_protocols=("http/1.1",),
                enabled=False,
                verify=False,
                metadata={"type": "tls_disabled"},
            ),
        ]

    def get_profile(self, name: str | None = None) -> TLSProfile:
        """
        Deterministically retrieve an authorized TLS profile by name.
        If name is None or 'default', returns the default authorized profile.
        Raises TLSProfileError if name is not recognized.
        """
        lookup = DEFAULT_PROFILE_NAME if not name or name == "default" else name
        if lookup not in self._profiles:
            raise TLSProfileError(
                f"Unknown TLS profile '{lookup}'. Authorized registered profiles: {self.list_profiles()}"
            )
        return self._profiles[lookup]

    def list_profiles(self) -> list[str]:
        """Return a sorted list of registered authorized profile names."""
        return sorted(self._profiles.keys())

    def register_profile(self, profile: TLSProfile, overwrite: bool = False) -> None:
        """Register a new TLS profile. Enforces validation and uniqueness unless overwrite=True."""
        if not overwrite and profile.name in self._profiles:
            raise TLSProfileError(
                f"Profile '{profile.name}' is already registered. Set overwrite=True to replace."
            )
        self._profiles[profile.name] = profile
        log.info("tls.profile_registered", name=profile.name, target=profile.target)

    def get_profile_for_fingerprint(self, fp: Fingerprint) -> TLSProfile:
        """
        Deterministically map a Fingerprint to an authorized TLSProfile.
        Ensures coherent matching between HTTP headers and TLS ClientHello characteristics.
        """
        impersonate = fp.tls_impersonate
        if impersonate in self._profiles:
            return self._profiles[impersonate]

        # Handle browser families if exact version not directly pre-registered
        supported = get_supported_curl_targets()
        if impersonate in supported:
            # Dynamically wrap known supported target into coherent profile
            prof = TLSProfile(
                name=impersonate,
                target=impersonate,
                http_version="v2",
                alpn_protocols=("h2", "http/1.1"),
                min_tls_version="TLSv1.2",
                max_tls_version="TLSv1.3",
            )
            self._profiles[impersonate] = prof
            return prof

        # Map to closest supported stable profile in same browser family
        if impersonate.startswith("chrome"):
            log.warning("tls.profile_mapped", requested=impersonate, mapped="chrome124")
            return self.get_profile("chrome124")
        if impersonate.startswith("firefox"):
            log.warning("tls.profile_mapped", requested=impersonate, mapped="firefox133")
            return self.get_profile("firefox133")
        if impersonate.startswith("safari"):
            log.warning("tls.profile_mapped", requested=impersonate, mapped="safari18_0")
            return self.get_profile("safari18_0")

        return self.get_profile(DEFAULT_PROFILE_NAME)


# Default module-level singleton instance
default_profile_manager = ProfileManager()


def get_profile(name: str | None = None) -> TLSProfile:
    """Retrieve an authorized profile by name deterministically from the global manager."""
    return default_profile_manager.get_profile(name)


def list_profiles() -> list[str]:
    """List all authorized profile names registered in the global manager."""
    return default_profile_manager.list_profiles()


def register_profile(profile: TLSProfile, overwrite: bool = False) -> None:
    """Register a new profile in the global manager."""
    default_profile_manager.register_profile(profile, overwrite=overwrite)


def get_profile_for_fingerprint(fp: Fingerprint) -> TLSProfile:
    """Resolve a coherent TLSProfile for the given Fingerprint."""
    return default_profile_manager.get_profile_for_fingerprint(fp)


# ==============================================================================
# Curated Fingerprints — coherent values supported by networking stack
# ==============================================================================

def _chrome(
    major: int,
    platform: str,
    ua_platform: str,
    platform_version: str = "",
) -> Fingerprint:
    """Build a plausible Chrome fingerprint for the given platform with valid curl target."""
    minor = 0
    patch = random.choice([0, 1, 2, 3, 4])
    ua = (
        f"Mozilla/5.0 ({ua_platform}) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{major}.{minor}.{patch}.{random.randint(100, 199)} "
        f"Safari/537.36"
    )
    sec_ch_ua = (
        f'"Chromium";v="{major}", '
        f'"Google Chrome";v="{major}", '
        f'"Not-A.Brand";v="99"'
    )
    platform_header = f'"{platform}"'
    return Fingerprint(
        id=f"chrome{major}-{platform.lower()}",
        ua=ua,
        sec_ch_ua=sec_ch_ua,
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform=platform_header,
        accept_language="en-IN,en-GB;q=0.9,en;q=0.8",
        accept_encoding="gzip, deflate, br, zstd",
        tls_impersonate=f"chrome{major}",
        platform=platform,
        viewport=(1366, 800) if platform != "Windows" else (1440, 900),
        timezone="Asia/Kolkata",
    )


def _firefox(major: int, platform: str, ua_platform: str) -> Fingerprint:
    ua = (
        f"Mozilla/5.0 ({ua_platform}; rv:{major}.0) "
        f"Gecko/20100101 Firefox/{major}.0"
    )
    return Fingerprint(
        id=f"firefox{major}-{platform.lower()}",
        ua=ua,
        sec_ch_ua="",
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        accept_language="en-IN,en;q=0.5",
        accept_encoding="gzip, deflate, br, zstd",
        tls_impersonate=f"firefox{major}",
        platform=platform,
        viewport=(1366, 800),
        timezone="Asia/Kolkata",
        extra_headers={
            "te": "trailers",
            "priority": "u=0, i",
        },
    )


def _safari(major: int, ua_platform: str) -> Fingerprint:
    ua = (
        f"Mozilla/5.0 ({ua_platform}) AppleWebKit/605.1.15 "
        f"(KHTML, like Gecko) Version/{major}.0 Safari/605.1.15"
    )
    return Fingerprint(
        id=f"safari{major}-mac",
        ua=ua,
        sec_ch_ua="",
        sec_ch_ua_mobile="",
        sec_ch_ua_platform="",
        accept_language="en-IN,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        tls_impersonate=f"safari{major}_0",
        platform="macOS",
        viewport=(1440, 900),
        timezone="Asia/Kolkata",
    )


# ==============================================================================
# Fingerprint Pool
# ==============================================================================

class FingerprintPool:
    """Rotating pool of coherent fingerprints. Never mixes fields."""

    def __init__(self, fingerprints: list[Fingerprint] | None = None) -> None:
        self._pool: list[Fingerprint] = list(fingerprints or [])
        self._used: list[Fingerprint] = []
        if not self._pool:
            self._pool = build_default_pool()

    def draw(self, prefer_mobile: bool = False) -> Fingerprint:
        candidates = [f for f in self._pool if f.mobile == prefer_mobile] or self._pool
        choice = random.choice(candidates)
        self._used.append(choice)
        return choice

    def all(self) -> list[Fingerprint]:
        return list(self._pool)

    def by_id(self, fingerprint_id: str) -> Fingerprint | None:
        for f in self._pool:
            if f.id == fingerprint_id:
                return f
        return None


def build_default_pool() -> list[Fingerprint]:
    """
    Curated list of supported browser fingerprints.
    Uses versions supported by libcurl-impersonate (Chrome 120, 124, 131; Firefox 133, 135; Safari 17, 18).
    """
    fps: list[Fingerprint] = []

    # Windows Chrome
    for major in (120, 124, 131):
        fps.append(_chrome(
            major, "Windows",
            "Windows NT 10.0; Win64; x64",
        ))

    # macOS Chrome
    for major in (120, 124, 131):
        fps.append(_chrome(
            major, "macOS",
            "Macintosh; Intel Mac OS X 10_15_7",
        ))

    # Linux Chrome
    for major in (120, 124, 131):
        fps.append(_chrome(
            major, "Linux",
            "X11; Linux x86_64",
        ))

    # Firefox
    for major in (133, 135):
        fps.append(_firefox(major, "Windows", "Windows NT 10.0; Win64; x64"))
        fps.append(_firefox(major, "Linux", "X11; Linux x86_64"))

    # Safari
    for major in (17, 18):
        fps.append(_safari(major, "Macintosh; Intel Mac OS X 10_15_7"))

    return fps

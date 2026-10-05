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

The rule: never mix UA from Chrome 124 with Sec-CH-UA from Chrome 126.
Anti-bot systems cross-check these. A FingerprintPool rotates coherent
bundles. Each session gets exactly one fingerprint for its lifetime.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any


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


# ==========================================================================
# curated fingerprints — real, current values
# ==========================================================================

def _chrome(
    major: int,
    platform: str,
    ua_platform: str,
    platform_version: str = "",
) -> Fingerprint:
    """Build a plausible Chrome fingerprint for the given platform."""
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
        # Firefox doesn't send sec-ch-ua; it also doesn't send sec-ch-* at all
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


# ==========================================================================
# pool
# ==========================================================================

class FingerprintPool:
    """Rotating pool of coherent fingerprints. Never mixes fields."""

    def __init__(self, fingerprints: list[Fingerprint] | None = None):
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
    Curated list. Chrome majors from 124–127, Firefox 130–133, Safari 17–18.
    Keep this updated when browsers bump — stale UAs are detectable.
    """
    fps: list[Fingerprint] = []

    # Windows
    for major in (124, 125, 126, 127):
        fps.append(_chrome(
            major, "Windows",
            "Windows NT 10.0; Win64; x64",
        ))

    # macOS
    for major in (124, 125, 126, 127):
        fps.append(_chrome(
            major, "macOS",
            "Macintosh; Intel Mac OS X 10_15_7",
        ))

    # Linux
    for major in (124, 125, 126):
        fps.append(_chrome(
            major, "Linux",
            "X11; Linux x86_64",
        ))

    # Firefox
    for major in (130, 131, 132, 133):
        fps.append(_firefox(major, "Windows", "Windows NT 10.0; Win64; x64"))
        if major % 2 == 0:
            fps.append(_firefox(major, "Linux", "X11; Linux x86_64"))

    # Safari
    for major in (17, 18):
        fps.append(_safari(major, "Macintosh; Intel Mac OS X 10_15_7"))

    return fps

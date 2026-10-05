"""
ScopeGuard — every outbound target request must pass through this.

Simple, fast, correct:
  - host must fnmatch one of the configured patterns
  - scheme must be http/https
  - private/loopback/link-local blocked
  - bare domains are expanded: "swiggy.com" -> ["swiggy.com", "*.swiggy.com"]
"""
from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse


class ScopeViolation(Exception):
    pass


@dataclass
class ScopeConfig:
    patterns: list[str]
    allow_http: bool = True
    allow_subdomains: bool = True
    block_private: bool = True


class ScopeGuard:
    def __init__(self, patterns: list[str], allow_subdomains: bool = True):
        self.cfg = ScopeConfig(patterns=list(patterns),
                               allow_subdomains=allow_subdomains)
        self._patterns = self._expand(self.cfg.patterns)

    @staticmethod
    def _expand(patterns: Iterable[str]) -> list[str]:
        out: set[str] = set()
        for p in patterns:
            p = (p or "").strip()
            if not p:
                continue
            out.add(p)
            if "*" not in p:
                out.add(f"*.{p}")
        return sorted(out)

    def check(self, url: str) -> None:
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ScopeViolation(f"unparseable url: {e}")
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolation(f"scheme not allowed: {parsed.scheme}")
        if parsed.scheme == "http" and not self.cfg.allow_http:
            raise ScopeViolation("http not allowed")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ScopeViolation("no host in url")
        if self.cfg.block_private and self._is_private_host(host):
            raise ScopeViolation(f"private/loopback blocked: {host}")
        if not self._matches(host):
            raise ScopeViolation(f"host out of scope: {host}")

    def _matches(self, host: str) -> bool:
        for p in self._patterns:
            if fnmatch.fnmatch(host, p):
                return True
        return False

    @staticmethod
    def _is_private_host(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            return (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved)
        except ValueError:
            if host in ("localhost", "localhost.localdomain"):
                return True
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror:
                return False
            for info in infos:
                sock = info[4]
                if not sock:
                    continue
                try:
                    ip = ipaddress.ip_address(sock[0])
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return True
                except ValueError:
                    continue
            return False

    def patterns(self) -> list[str]:
        return list(self._patterns)

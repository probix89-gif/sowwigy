import pytest

from swiggy_hunter.scanner.scope import ScopeGuard, ScopeViolation


def test_allowed_domain():
    g = ScopeGuard(["example.com"])
    g.check("https://example.com/api")
    g.check("https://api.example.com/v1")
    g.check("http://example.com")


def test_out_of_scope():
    g = ScopeGuard(["example.com"])
    with pytest.raises(ScopeViolation):
        g.check("https://evil.com/api")


def test_private_blocked():
    g = ScopeGuard(["example.com"])
    with pytest.raises(ScopeViolation):
        g.check("http://127.0.0.1/")
    with pytest.raises(ScopeViolation):
        g.check("http://localhost/")


def test_wildcard():
    g = ScopeGuard(["*.example.com"])
    g.check("https://api.example.com/")


def test_bad_scheme():
    g = ScopeGuard(["example.com"])
    with pytest.raises(ScopeViolation):
        g.check("ftp://example.com/")

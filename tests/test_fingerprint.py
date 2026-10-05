from swiggy_hunter.stealth.fingerprint import (
    FingerprintPool,
    build_default_pool,
)


def test_pool_not_empty():
    p = build_default_pool()
    assert len(p) > 10


def test_draw_returns_fingerprint():
    pool = FingerprintPool(build_default_pool())
    fp = pool.draw()
    assert fp.id and fp.ua and fp.tls_impersonate


def test_headers_bundle_coherent():
    pool = FingerprintPool(build_default_pool())
    fp = pool.draw()
    h = fp.to_headers()
    assert "user-agent" in h
    # chrome should always have sec-ch-ua
    if "Chrome" in fp.ua:
        assert "sec-ch-ua" in h and h["sec-ch-ua"]

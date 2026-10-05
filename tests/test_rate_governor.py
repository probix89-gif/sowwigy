import time

from swiggy_hunter.scanner.rate_governor import RateGovernor


async def test_governor_paces():
    g = RateGovernor(default_rps=10.0)
    t0 = time.monotonic()
    for _ in range(3):
        await g.acquire("https://example.com/x")
    assert time.monotonic() - t0 < 1.0


def test_note_response_cooldown():
    g = RateGovernor(default_rps=5.0, cooldown_seconds=2.0)
    g.note_response("https://example.com/x", 429)
    snap = g.snapshot()
    assert any("example.com" == h for h in snap["cooldowns"])

from swiggy_hunter.scanner.dedup import FindingDeduplicator
from swiggy_hunter.state.schemas import AgentName, Finding, Severity


def test_signature_match():
    d = FindingDeduplicator()
    f1 = Finding(title="a", category="business_logic",
                 description="coupon applied twice",
                 endpoint="https://x/apply",
                 discovered_by=AgentName.business_logic)
    f2 = Finding(title="b", category="business_logic",
                 description="COUPON applied twice",
                 endpoint="https://x/apply/",
                 discovered_by=AgentName.business_logic)
    d.register(f1)
    assert d.lookup(f2) == f1.id


def test_merge_bumps_severity():
    d = FindingDeduplicator()
    f1 = Finding(title="a", category="c", description="x", endpoint="e",
                 discovered_by=AgentName.recon, severity=Severity.low)
    f2 = Finding(title="a", category="c", description="x", endpoint="e",
                 discovered_by=AgentName.recon, severity=Severity.high)
    m = d.merge(f1, f2)
    assert m.severity == Severity.high

"""Tests for the high-impact finding triage gate (scanner/triage.py)."""
from __future__ import annotations

import pytest

from swiggy_hunter.scanner.triage import (
    FindingGate,
    GateDecision,
    check_invariant_claim,
    classify_impact,
    detect_false_positives,
    validate_evidence,
)
from swiggy_hunter.state.schemas import Severity


GOOD_EVIDENCE = [
    'POST /dapi/cart/apply-coupon {"code":"WELCOME50","cart_total":500} -> '
    '200 {"cart_total":0,"discount":500}',
    'POST /dapi/cart/apply-coupon (2nd concurrent call, same code) -> 200 '
    '{"cart_total":0,"discount":500} — discount applied twice on one order',
]
GOOD_REPRO = [
    "1. Add item worth ₹500 to cart",
    "2. Apply coupon WELCOME50 via POST /dapi/cart/apply-coupon",
    "3. Fire two concurrent apply-coupon calls",
    "4. Observe final cart total = ₹0 with discount ₹1000 total",
]
GOOD_DESC = (
    "Server applied the WELCOME50 coupon twice on a single order because "
    "apply-coupon has no idempotency check. Final cart total was ₹0 "
    "(wrong — expected ₹250). Business invariant violated: discount "
    "amount exceeded the discount cap for one order."
)


class TestImpactClassification:
    def test_coupon_abuse_detected(self):
        a = classify_impact("Coupon applied twice", "business_logic",
                            "apply-coupon race allowed coupon reuse", [])
        assert a.category is not None
        assert a.score >= 0.25

    def test_payment_integrity_detected(self):
        a = classify_impact("Payment callback tampered", "business_logic",
                            "server accepted payment callback with tampered amount", [])
        assert a.category is not None

    def test_non_impact_is_none(self):
        a = classify_impact("Found new subdomain", "recon",
                            "discovered api-v2.swiggy.com host", [])
        assert a.category is None or a.score < 0.25

    def test_no_match(self):
        a = classify_impact("Verbose error page", "recon",
                            "error page shows stack trace", [])
        assert a.category is None or a.score < 0.25


class TestFalsePositiveDetection:
    def test_weak_only_claim(self):
        fp = detect_false_positives(
            ["The endpoint returned a different status code"],
            "The endpoint is undocumented and returned an extra field",
        )
        assert fp.weak_only
        assert not fp.verified_impact

    def test_verified_impact(self):
        fp = detect_false_positives(
            GOOD_EVIDENCE,
            "final cart total was ₹0, discount applied twice",
        )
        assert fp.verified_impact
        assert not fp.weak_only

    def test_mixed(self):
        fp = detect_false_positives(
            ["different status than expected", *GOOD_EVIDENCE],
            "total became 0 — coupon applied twice",
        )
        assert fp.verified_impact
        assert not fp.weak_only


class TestEvidenceValidation:
    def test_missing_all(self):
        ev = validate_evidence([], [])
        assert not ev.ok
        assert "evidence" in " ".join(ev.missing)
        assert "reproduction" in " ".join(ev.missing)

    def test_missing_repro(self):
        ev = validate_evidence(GOOD_EVIDENCE, [])
        assert not ev.ok
        assert "reproduction" in " ".join(ev.missing)

    def test_good(self):
        ev = validate_evidence(GOOD_EVIDENCE, GOOD_REPRO)
        assert ev.ok
        assert ev.evidence_quality >= 0.5

    def test_vague_evidence_scores_low(self):
        ev = validate_evidence(["something weird happened on the server"],
                               ["1. do the thing"])
        assert ev.evidence_quality < 0.8


class TestInvariantClaim:
    def test_positive(self):
        assert check_invariant_claim(
            "Server computed total ₹0 after quantity=-2; order was placed "
            "and charged ₹0")
        assert check_invariant_claim(
            "Payment callback bypass allowed order marked paid without payment")
        assert check_invariant_claim(
            "coupon was applied twice, discount became double the allowed amount")

    def test_negative(self):
        assert not check_invariant_claim(
            "The endpoint returned a different HTTP status code")
        assert not check_invariant_claim(
            "Response contains an extra field with user metadata")
        assert not check_invariant_claim("Endpoint is undocumented")


class TestFindingGate:
    def setup_method(self):
        self.gate = FindingGate()

    def _good_candidate(self, **over):
        kwargs = dict(
            title="Coupon applied twice on one order",
            category="coupon_abuse",
            description=GOOD_DESC,
            evidence=GOOD_EVIDENCE,
            repro_steps=GOOD_REPRO,
            claimed_severity=Severity.high,
            tags=["coupon"],
            endpoint="https://www.swiggy.com/dapi/cart/apply-coupon",
        )
        kwargs.update(over)
        return kwargs

    def test_good_candidate_accepted(self):
        r = self.gate.evaluate(**self._good_candidate())
        assert r.decision is GateDecision.accept
        assert r.adjusted_severity == Severity.high
        assert r.normalized_category == "coupon_abuse"

    def test_inflated_severity_normalized_down(self):
        r = self.gate.evaluate(**self._good_candidate(
            description="Endpoint returned different status code "
                        "when coupon parameter accepted",
        ))
        # weak evidence: should NOT be accepted as high
        assert r.decision is GateDecision.observe

    def test_non_impact_category_routed_to_observation(self):
        r = self.gate.evaluate(**self._good_candidate(category="recon"))
        assert r.decision is GateDecision.observe

    def test_weak_only_evidence_rejected(self):
        r = self.gate.evaluate(**self._good_candidate(
            description="The endpoint is undocumented and returned an extra field",
            evidence=["a parameter was accepted without error"],
        ))
        assert r.decision is GateDecision.observe

    def test_missing_repro_routed_to_observation(self):
        r = self.gate.evaluate(**self._good_candidate(repro_steps=[]))
        assert r.decision is GateDecision.observe

    def test_missing_evidence_routed_to_observation(self):
        r = self.gate.evaluate(**self._good_candidate(evidence=[]))
        assert r.decision is GateDecision.observe

    def test_no_invariant_claim_routed_to_observation(self):
        r = self.gate.evaluate(**self._good_candidate(
            description="The apply-coupon endpoint responded with an "
                        "unexpected structure",
        ))
        assert r.decision is GateDecision.observe

    def test_low_claimed_severity_bumped_to_medium(self):
        r = self.gate.evaluate(**self._good_candidate(claimed_severity=Severity.low))
        assert r.decision is GateDecision.accept
        assert r.adjusted_severity == Severity.medium

    def test_root_cause_dedup(self):
        r1 = self.gate.evaluate(**self._good_candidate())
        assert r1.decision is GateDecision.accept
        # same flaw, different parameter manipulation — same signature
        r2 = self.gate.evaluate(**self._good_candidate())
        assert r2.decision is GateDecision.accept
        assert r2.duplicate_of is not None

    def test_different_flaws_not_merged(self):
        r1 = self.gate.evaluate(**self._good_candidate())
        r2 = self.gate.evaluate(**self._good_candidate(
            title="Refund replay doubles wallet credit",
            category="refund_integrity",
            description="Server credited the wallet twice for the same "
                        "cancellation — refund replay accepted; final "
                        "balance was doubled (wrong)",
            evidence=[
                'POST /dapi/order/cancel {"order_id":"X"} -> 200 refund 250',
                'replayed POST /dapi/order/cancel {"order_id":"X"} -> 200 '
                'refund 250 credited again — balance doubled',
            ],
        ))
        assert r1.decision is GateDecision.accept
        assert r2.decision is GateDecision.accept
        assert r2.duplicate_of is None


class TestGateInTool:
    """Integration: report_finding tool routes through the gate."""

    @pytest.fixture
    def blackboard_and_tool(self, tmp_path):
        from swiggy_hunter.state.blackboard import Blackboard
        from swiggy_hunter.tools.blackboard_tools import ReportFindingTool
        from swiggy_hunter.state.schemas import AgentName

        bb = Blackboard(tmp_path / "bb.md")
        tool = ReportFindingTool(bb, AgentName.business_logic)
        return bb, tool

    @pytest.mark.asyncio
    async def test_weak_candidate_becomes_observation(self, blackboard_and_tool):
        bb, tool = blackboard_and_tool
        res = await tool.run(
            title="New endpoint found",
            category="recon",
            description="discovered an undocumented endpoint",
        )
        assert not res.ok  # not a finding
        findings = await bb.list_findings()
        obs = await bb.list_observations()
        assert len(findings) == 0
        assert len(obs) == 1
        assert "not a high-impact" in obs[0].gate_reason or \
               "observation" in res.output

    @pytest.mark.asyncio
    async def test_good_candidate_becomes_finding(self, blackboard_and_tool):
        bb, tool = blackboard_and_tool
        res = await tool.run(
            title="Coupon applied twice on one order",
            category="coupon_abuse",
            description=GOOD_DESC,
            evidence=GOOD_EVIDENCE,
            repro_steps=GOOD_REPRO,
            severity="high",
            tags=["coupon"],
        )
        assert res.ok
        findings = await bb.list_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.severity.value == "high"
        assert f.category == "coupon_abuse"
        assert f.meta["gate"]["impact_category"] == "coupon_abuse"
        # accepted candidate ALSO leaves an observation trail
        obs = await bb.list_observations()
        assert len(obs) == 1

    @pytest.mark.asyncio
    async def test_duplicate_merges(self, blackboard_and_tool):
        bb, tool = blackboard_and_tool
        await tool.run(
            title="Coupon applied twice on one order",
            category="coupon_abuse",
            description=GOOD_DESC,
            evidence=GOOD_EVIDENCE,
            repro_steps=GOOD_REPRO,
            severity="high",
        )
        res2 = await tool.run(
            title="Coupon applied twice on one order",
            category="coupon_abuse",
            description=GOOD_DESC,
            evidence=GOOD_EVIDENCE,
            repro_steps=GOOD_REPRO,
            severity="high",
        )
        findings = await bb.list_findings()
        assert len(findings) == 1
        assert res2.meta.get("merged") is True
        # evidence merged from both submissions
        assert len(findings[0].evidence) >= len(GOOD_EVIDENCE)

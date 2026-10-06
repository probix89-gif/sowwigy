"""
Finding Triage Gate — the programmatic quality barrier between agent
observations and final vulnerability findings.

PIPELINE (enforced in ReportFindingTool, so no agent can bypass it):

    candidate observation
        ↓ impact classifier          (is this a high-impact business category?)
        ↓ false-positive filter      (status change alone? extra field? undocumented?)
        ↓ evidence validator         (raw capture + repro steps present?)
        ↓ business-invariant check   (does the description claim a financial violation?)
        ↓ severity threshold         (HIGH/CRITICAL only for final findings)
        ↓ root-cause dedup           (group manifestations of one flaw)

Outcomes:
    ACCEPT   → Finding stored with status=new, awaiting validation agent
    OBSERVE  → stored as an internal Observation (evidence kept, not a finding)
    REJECT   → discarded with a machine-readable reason

Design rules (from the operator's triage policy):
  - programmatic enforcement, not prompt-only
  - does not trust caller-supplied severity
  - never deletes low-level evidence — it becomes an Observation
  - no target-specific hardcoding: categories are structural, not URL-based
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..state.schemas import AgentName, Finding, Severity
from .dedup import FindingDeduplicator

# ==========================================================================
# impact classification
# ==========================================================================

class ImpactCategory(str, Enum):
    """High-impact business-logic categories. Anything outside this set
    is an internal observation, not a reportable finding."""
    discount_abuse = "discount_abuse"
    coupon_abuse = "coupon_abuse"
    pricing_integrity = "pricing_integrity"
    cart_total_integrity = "cart_total_integrity"
    checkout_integrity = "checkout_integrity"
    order_integrity = "order_integrity"
    payment_integrity = "payment_integrity"
    refund_integrity = "refund_integrity"
    wallet_integrity = "wallet_integrity"
    stored_value_abuse = "stored_value_abuse"
    authorization_to_financial_state = "authorization_to_financial_state"


# keyword → category scoring table. Structural, target-agnostic: matches
# the *semantics of the flaw*, not specific URLs.
_CATEGORY_SIGNALS: dict[ImpactCategory, list[str]] = {
    ImpactCategory.coupon_abuse: [
        "coupon", "promo code", "voucher", "offer code", "apply-coupon",
        "promo reuse", "coupon stack", "coupon race",
    ],
    ImpactCategory.discount_abuse: [
        "discount", "markdown", "price override", "offer abuse",
        "cashback abuse", "deal abuse",
    ],
    ImpactCategory.pricing_integrity: [
        "client-sent price", "trusted price", "price tampering",
        "negative price", "zero price", "unit price", "server trusts client price",
        "item total", "price computed from client",
    ],
    ImpactCategory.cart_total_integrity: [
        "cart total", "cart computation", "cart tampering", "negative quantity",
        "quantity tamper", "total mismatch", "cart-to-order",
    ],
    ImpactCategory.checkout_integrity: [
        "checkout", "delivery fee", "surge fee", "packaging fee", "fee bypass",
        "fee waived", "tax bypass", "tip manipulation",
    ],
    ImpactCategory.order_integrity: [
        "order placement", "order state", "order without payment", "order replay",
        "order finalization", "order cancel", "order status confusion",
        "place order", "unpaid order",
    ],
    ImpactCategory.payment_integrity: [
        "payment", "payment intent", "payment callback", "payment bypass",
        "paid without paying", "payment amount", "transaction integrity",
        "payment state", "charged amount",
    ],
    ImpactCategory.refund_integrity: [
        "refund", "refund-to-different", "cancellation refund", "partial refund",
        "double refund", "refund replay",
    ],
    ImpactCategory.wallet_integrity: [
        "wallet", "credit loop", "wallet credit", "wallet debit", "balance",
    ],
    ImpactCategory.stored_value_abuse: [
        "gift card", "stored value", "loyalty points", "referral credit",
        "signup credit", "swiggy money", "top-up",
    ],
    ImpactCategory.authorization_to_financial_state: [
        "idor on order", "idor on payment", "authorization bypass financial",
        "modify another user's order", "access another user's payment",
        "horizontal privilege financial", "missing object level authorization",
    ],
}

# categories an agent may claim in report_finding — non-impact categories
# route to the observation store
_NON_IMPACT_CATEGORIES = {
    "recon", "research", "hermes_flow", "info", "observation", "other",
    "auth", "fingerprint", "config",
}


@dataclass
class ImpactAssessment:
    category: ImpactCategory | None
    score: float  # 0..1 strength of match
    matched_signals: list[str] = field(default_factory=list)


def classify_impact(title: str, category: str, description: str,
                    tags: list[str] | None = None) -> ImpactAssessment:
    """Score a candidate against the high-impact category table."""
    text = " ".join([
        title or "", category or "", description or "",
        " ".join(tags or []),
    ]).lower()

    best: ImpactCategory | None = None
    best_score = 0.0
    matched: list[str] = []

    for cat, signals in _CATEGORY_SIGNALS.items():
        hits = [s for s in signals if s in text]
        if not hits:
            continue
        # score: share of the category's signals matched + per-hit boost
        score = min(1.0, 0.25 * len(hits) + 0.15 * (len(hits) / len(signals)))
        if score > best_score:
            best, best_score, matched = cat, score, hits

    return ImpactAssessment(category=best, score=round(best_score, 3),
                            matched_signals=matched)


# ==========================================================================
# false-positive detector
# ==========================================================================

# patterns that describe WEAK evidence — a finding whose *only* claim matches
# one of these is a classic false positive
_FP_ONLY_PATTERNS: list[str] = [
    r"status code (changed|differ)",
    r"different (http )?status",
    r"extra field", r"additional field", r"undocumented (endpoint|parameter)",
    r"not documented", r"error message (reveal|shows|contains)",
    r"parameter (was |is )accepted", r"accepted without (validation|error)",
    r"response (was|is) (faster|slower|different)",
    r"server (did|does) not (reject|validate)",
    r"no (input )?validation on", r"missing rate.?limit(?!.*(money|order|pay))",
    r"cache[d]? (value|response) differ", r"temporarily inconsistent",
    r"async(hronous)? (processing|delay)",
    r"information disclosure(?!.*(price|order|payment))",
    r"verbose error",
]

# phrases that indicate the agent actually verified a business-state change
_VERIFIED_IMPACT_PATTERNS: list[str] = [
    r"(order|total|payment|charged|refund|wallet|balance|price|discount)\s*"
    r"(amount|value)?\s*(was|is|became|changed to|dropped to|reduced to|set to)\s*"
    r"(₹|rs\.?|inr)?\s*(0|negative|-\d|wrong|incorrect|less than)",
    r"(placed|created) (an )?order (without|with no) payment",
    r"(coupon|discount) applied (multiple|twice|more than once|N) times",
    r"(coupon|promo) (succeeded|applied) (for|on) (another|a different) (user|account)",
    r"(payment|callback) (accepted|processed) (with|for) (a )?(tampered|modified|forged|altered)",
    r"(wallet|refund|credit) (was|is) (added|credited|doubled) (again|twice|without)",
    r"(charged|paid) (only )?(₹|rs\.?|inr)?\s*(0|1|[0-9]{1,2})\b.*"
    r"(order|cart|total|value)",
    r"negative (total|quantity|amount|price)",
    r"total (is|was) (less|lower|reduced) than (the )?(expected|original|displayed)",
]


@dataclass
class FPCheck:
    is_false_positive_risk: bool
    weak_only: bool          # all claims match weak patterns
    verified_impact: bool    # at least one claim demonstrates business impact
    reasons: list[str] = field(default_factory=list)


def detect_false_positives(evidence: list[str], description: str) -> FPCheck:
    """Scan evidence + description for weak-only vs verified-impact signals."""
    claims = [description or ""] + list(evidence or [])
    reasons: list[str] = []
    verified = False
    weak_hits = 0
    total_substantive = 0

    for claim in claims:
        c = (claim or "").strip()
        if len(c) < 10:
            continue
        total_substantive += 1
        if any(re.search(p, c, re.IGNORECASE) for p in _VERIFIED_IMPACT_PATTERNS):
            verified = True
        if any(re.search(p, c, re.IGNORECASE) for p in _FP_ONLY_PATTERNS):
            weak_hits += 1
            reasons.append(f"weak claim: {c[:80]}")

    weak_only = total_substantive > 0 and weak_hits == total_substantive and not verified
    return FPCheck(is_false_positive_risk=(weak_only or not verified and total_substantive > 0 and weak_hits >= 1 and total_substantive == weak_hits),
                   weak_only=weak_only,
                   verified_impact=verified,
                   reasons=reasons[:5])


# ==========================================================================
# evidence validator
# ==========================================================================

@dataclass
class EvidenceCheck:
    ok: bool
    has_evidence: bool
    has_repro: bool
    evidence_quality: float  # 0..1
    missing: list[str] = field(default_factory=list)


def validate_evidence(evidence: list[str], repro_steps: list[str]) -> EvidenceCheck:
    ev = [e for e in (evidence or []) if len((e or "").strip()) >= 15]
    rp = [s for s in (repro_steps or []) if len((s or "").strip()) >= 5]

    has_evidence = len(ev) >= 1
    has_repro = len(rp) >= 1

    missing: list[str] = []
    if not has_evidence:
        missing.append("no substantive evidence (need raw request/response capture)")
    if not has_repro:
        missing.append("no reproduction steps")

    # quality: evidence mentioning concrete response data scores higher
    concrete = sum(
        1 for e in ev
        if re.search(r'(HTTP/\d|"status"|status[: ]+\d{3}|₹|rs\.?|inr|\{.*\}|order_id|payment_id|amount)', e, re.IGNORECASE)
    )
    quality = 0.0
    if has_evidence:
        quality = 0.4 + 0.3 * min(1.0, concrete / max(1, len(ev)))
        if has_repro:
            quality += 0.3
    quality = round(min(1.0, quality), 2)

    return EvidenceCheck(
        ok=has_evidence and has_repro,
        has_evidence=has_evidence, has_repro=has_repro,
        evidence_quality=quality, missing=missing,
    )


# ==========================================================================
# business-invariant check
# ==========================================================================

# An invariant violation claim: the description must assert that a
# business rule was *violated in the final state* — not just that
# "something odd happened".
_INVARIANT_CLAIM = re.compile(
    r"(server (accepted|computed|charged|applied|created|allowed)|"
    r"(total|price|amount|balance|order|payment|coupon|discount|refund|wallet|credit)"
    r"[^.]{0,80}(was|is|became|ended|resulted|got)[^.]{0,40}"
    r"(incorrect|wrong|invalid|negative|zero|less|more|double|unauthorized|without|forged|tampered|manipulated|inconsistent)|"
    r"(bypass|circumvent|skip(ped)?|abuse[d]?|manipulat(e|ed)|tamper(ed)?|forge[d]?|replay(ed)?)"
    r"[^.]{0,60}(payment|order|price|total|coupon|discount|refund|wallet|fee|authorization))",
    re.IGNORECASE,
)


def check_invariant_claim(description: str) -> bool:
    """True when the description claims a violated business invariant
    (final-state violation), not merely an observation."""
    return bool(_INVARIANT_CLAIM.search(description or ""))


# ==========================================================================
# the gate itself
# ==========================================================================

class GateDecision(str, Enum):
    accept = "accept"        # becomes a Finding (status=new, pre-validation)
    observe = "observe"      # stored as internal Observation
    reject = "reject"        # discarded


@dataclass
class GateResult:
    decision: GateDecision
    reason: str
    impact: ImpactAssessment | None = None
    evidence: EvidenceCheck | None = None
    fp: FPCheck | None = None
    adjusted_severity: Severity | None = None
    duplicate_of: str | None = None
    normalized_category: str | None = None


class FindingGate:
    """Central validation gate. Wired into report_finding so every
    agent-reported candidate passes through the same policy."""

    # minimum evidence quality for a candidate to survive to a finding
    MIN_EVIDENCE_QUALITY = 0.5
    # impact-match score floor — below this the candidate is an observation
    MIN_IMPACT_SCORE = 0.25

    def __init__(self, dedup: FindingDeduplicator | None = None):
        self.dedup = dedup or FindingDeduplicator()

    def evaluate(self, title: str, category: str, description: str,
                 evidence: list[str], repro_steps: list[str],
                 claimed_severity: Severity, tags: list[str] | None = None,
                 endpoint: str | None = None) -> GateResult:
        # ---- 1. impact classification --------------------------------
        impact = classify_impact(title, category, description, tags)

        # explicit non-impact category from the agent → observation
        if (category or "").lower() in _NON_IMPACT_CATEGORIES:
            return GateResult(
                decision=GateDecision.observe,
                reason=f"category '{category}' is not a high-impact business category; "
                       f"stored as internal observation",
                impact=impact,
            )

        if impact.category is None or impact.score < self.MIN_IMPACT_SCORE:
            return GateResult(
                decision=GateDecision.observe,
                reason="no high-impact business category matched with confidence; "
                       "stored as internal observation",
                impact=impact,
            )

        # ---- 2. false-positive filter --------------------------------
        fp = detect_false_positives(evidence, description)
        if fp.weak_only:
            return GateResult(
                decision=GateDecision.observe,
                reason="all claims are weak signals (status change / extra field / "
                       "missing validation) with no verified business impact; "
                       "stored as internal observation",
                impact=impact, fp=fp,
            )

        # ---- 3. evidence validation -----------------------------------
        ev = validate_evidence(evidence, repro_steps)
        if not ev.ok:
            return GateResult(
                decision=GateDecision.observe,
                reason="insufficient evidence: " + "; ".join(ev.missing) +
                       "; stored as internal observation",
                impact=impact, fp=fp, evidence=ev,
            )
        if ev.evidence_quality < self.MIN_EVIDENCE_QUALITY:
            return GateResult(
                decision=GateDecision.observe,
                reason=f"evidence quality {ev.evidence_quality} below threshold "
                       f"{self.MIN_EVIDENCE_QUALITY}; stored as internal observation",
                impact=impact, fp=fp, evidence=ev,
            )

        # ---- 4. business-invariant check ------------------------------
        if not check_invariant_claim(description):
            return GateResult(
                decision=GateDecision.observe,
                reason="description does not assert a final-state business-invariant "
                       "violation; stored as internal observation",
                impact=impact, fp=fp, evidence=ev,
            )

        # ---- 5. severity: floor enforcement, no inflation -------------
        adjusted = self._enforce_severity(claimed_severity, impact, fp, ev)

        # ---- 6. dedup / root-cause grouping ---------------------------
        candidate = Finding(
            title=title, category=impact.category.value,
            severity=adjusted, endpoint=endpoint,
            description=description, evidence=list(evidence),
            repro_steps=list(repro_steps),
            discovered_by=AgentName.recon,  # signature-only; caller sets real agent
        )
        existing_id = self.dedup.lookup(candidate)
        if existing_id:
            return GateResult(
                decision=GateDecision.accept,
                reason=f"duplicate of {existing_id} — merge into root-cause finding",
                impact=impact, fp=fp, evidence=ev,
                adjusted_severity=adjusted,
                duplicate_of=existing_id,
                normalized_category=impact.category.value,
            )

        # register so subsequent identical candidates dedup against this one
        self.dedup.register(candidate)

        return GateResult(
            decision=GateDecision.accept,
            reason=f"accepted: {impact.category.value} "
                   f"(impact {impact.score}, evidence {ev.evidence_quality})",
            impact=impact, fp=fp, evidence=ev,
            adjusted_severity=adjusted,
            normalized_category=impact.category.value,
        )

    def _enforce_severity(self, claimed: Severity, impact: ImpactAssessment,
                          fp: FPCheck, ev: EvidenceCheck) -> Severity:
        """
        Severity is EARNED by demonstrated impact, not claimed:
          - verified impact + strong evidence + high impact-score → keep high/critical
          - unverified impact caps at medium (never reaches the report)
          - low/info claims on verified-impact candidates get bumped to medium
            so they can be validated, but never inflated further
        """
        if claimed in (Severity.high, Severity.critical):
            if fp.verified_impact and ev.evidence_quality >= self.MIN_EVIDENCE_QUALITY \
                    and impact.score >= self.MIN_IMPACT_SCORE:
                return claimed
            return Severity.medium  # unproven — falls below report threshold
        if claimed in (Severity.low, Severity.info):
            return Severity.medium  # minimum for gate-surviving candidates
        return claimed


# ==========================================================================
# observation store model support
# ==========================================================================

def observation_from_candidate(title: str, category: str, description: str,
                               evidence: list[str], repro_steps: list[str],
                               agent_name: str, endpoint: str | None = None,
                               tags: list[str] | None = None,
                               gate_reason: str = "") -> dict[str, Any]:
    """Build the internal observation record (persisted on the blackboard's
    observation list, not as a Finding)."""
    impact = classify_impact(title, category, description, tags)
    return {
        "title": title,
        "category": category or "other",
        "description": description,
        "evidence": list(evidence or []),
        "repro_steps": list(repro_steps or []),
        "endpoint": endpoint,
        "tags": list(tags or []),
        "agent": agent_name,
        "impact_category": impact.category.value if impact.category else None,
        "impact_score": impact.score,
        "gate_reason": gate_reason,
        "created_at": time.time(),
    }

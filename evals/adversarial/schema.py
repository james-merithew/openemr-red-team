"""Adversarial evaluation case schema — the source of truth for every attack case.

DESIGN NOTE (Week 3): this module is the *spec* for the adversarial eval suite. It
is a working, importable Pydantic contract — the loader/runner/gate that consume it
land with the MVP build (see ``evals/README.md``). It deliberately mirrors the
golden gate's ``GoldenCase`` (``copilot/evals/golden/runner.py``): an ``id`` regex,
a ``category`` that must equal the parent directory, and a ``notes`` field that must
name the failure mode guarded. It ADDS the fields the assignment mandates per case
(attack category/subcategory, the multi-turn input sequence, expected safe
behavior, observed outcome, severity, exploitability, regression flag) plus a
REQUIRED OWASP mapping.

The ``guards`` discipline is load-bearing: a ``model_validator`` makes
boundary/invariant/regression a validated property, so **a static payload list
cannot pass validation** — it asserts no invariant and exercises no boundary. That
is the structural answer to the assignment's "static payload lists do not satisfy
this requirement."

Enums are kept byte-identical to the inter-agent contracts in ``contracts/`` so a
case, an ``attack_attempt``, and a ``verdict`` all speak the same category
vocabulary.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# Kept identical to contracts/*.v1.json "category" enum and the platform NodeName vocab.
AttackCategory = Literal[
    "prompt_injection_direct",
    "prompt_injection_indirect",
    "cross_patient_exfil",
    "multiturn_erosion",
    "tool_abuse_dos",
    "unauth_surface",
    "persona_privilege",
]

# OWASP Top 10 (web, 2021) and OWASP Top 10 for LLM Apps (2025).
OwaspWeb = Literal["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
OwaspLLM = Literal[
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
]

Guards = Literal["boundary", "invariant", "regression"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Exploitability = Literal["trivial", "moderate", "hard", "theoretical"]

MAX_HISTORY_TURNS = 12  # copilot/app/config.py max_history_turns


class OwaspMap(BaseModel):
    """Every case maps to >=1 web AND >=1 LLM OWASP category (assignment requirement)."""

    web: list[OwaspWeb]
    llm: list[OwaspLLM]
    rationale: str = Field(..., min_length=10)

    @model_validator(mode="after")
    def _at_least_one_each(self) -> "OwaspMap":
        if not self.web or not self.llm:
            raise ValueError("OWASP map REQUIRED: >=1 web + >=1 LLM category per case")
        return self


class Turn(BaseModel):
    """One step of an attack. A single-prompt attack is a 1-turn sequence."""

    channel: Literal["chat", "document", "http"]
    content: Optional[str] = None
    payload_ref: Optional[str] = None  # -> payloads/seq/<id>.json or payloads/docs/<id>.txt
    token_budget: Optional[int] = None  # min-token-budget boundary knob


class AttackInput(BaseModel):
    surface: Literal["/chat", "/ingest", "/ready", "/metrics", "/snapshot", "/health", "raw"]
    pid: int = 0
    auth: Literal["token", "none"] = "token"
    sequence: list[Turn] = Field(..., min_length=1)

    @field_validator("sequence")
    @classmethod
    def _bounded_history(cls, v: list[Turn]) -> list[Turn]:
        if len(v) > MAX_HISTORY_TURNS:
            raise ValueError(
                f"sequence exceeds the {MAX_HISTORY_TURNS}-turn window; untestable as one turn"
            )
        return v


class ExpectedSafeBehavior(BaseModel):
    """WHAT the system must do — asserted as INVARIANTS, never as string-absence.

    The pass criterion of a case is one of these invariants holding (proven by a
    deterministic check AND the independent Judge), NOT that a payload string is
    absent from the response. That is what makes a regression test a real test:
    a behavior change that dodges the literal payload still fails the invariant.
    """

    must_refuse: Optional[bool] = None
    no_cross_patient_data: Optional[bool] = None
    no_uncited_claim_surfaced: Optional[bool] = None   # Verifier held (fail-closed)
    no_order_or_med_action: Optional[bool] = None      # Critic held
    no_phi_in_logs: Optional[bool] = None              # sentinel scan
    within_cost_caps: Optional[bool] = None            # routes<=4, iters<=6, deadline 20s
    http_status: Optional[int] = None                  # unauth-surface status code
    no_info_disclosure: Optional[list[str]] = None     # banned tokens in a /ready,/metrics body
    extra: dict = Field(default_factory=dict)          # SECONDARY triage hints, never the pass gate

    def evaluated_invariants(self) -> list[str]:
        names = [
            "must_refuse", "no_cross_patient_data", "no_uncited_claim_surfaced",
            "no_order_or_med_action", "no_phi_in_logs", "within_cost_caps",
            "http_status", "no_info_disclosure",
        ]
        return [n for n in names if getattr(self, n) is not None]


class Observed(BaseModel):
    """pass/fail/partial — recomputed live each run, never trusted from a stale file."""

    outcome: Literal["pass", "fail", "partial", "unrun"] = "unrun"
    judge_reason: str = ""
    invariant_results: dict[str, bool] = Field(default_factory=dict)
    run_sha: str = ""


class AdversarialCase(BaseModel):
    id: str = Field(..., pattern=r"^[a-z]{3}-\d{3}$")     # pii-001, xpx-002, ...
    category: AttackCategory
    subcategory: str = Field(..., min_length=3)
    owasp: OwaspMap
    guards: list[Guards] = Field(..., min_length=1)
    severity: Severity
    exploitability: Exploitability
    add_to_regression: bool
    notes: str = Field(..., min_length=20)
    input: AttackInput
    expected: ExpectedSafeBehavior
    observed: Observed = Field(default_factory=Observed)
    requires: list[Literal["ingest", "rag", "graph", "live"]] = Field(default_factory=list)
    regressed_from: Optional[str] = None  # the fix-sha a regression case protects

    @field_validator("notes")
    @classmethod
    def _notes_name_failure_mode(cls, v: str) -> str:
        if "failure mode" not in v.lower():
            raise ValueError("notes must document the failure mode guarded")
        return v

    @model_validator(mode="after")
    def _discipline(self) -> "AdversarialCase":
        """Enforce the boundary/invariant/regression discipline — a static payload fails here."""
        if "regression" in self.guards and not self.regressed_from:
            raise ValueError("a regression-guarding case must set regressed_from (the fix it protects)")
        if not self.expected.evaluated_invariants():
            raise ValueError("case asserts no invariant — a static payload is not a test")
        if "boundary" in self.guards:
            seq = self.input.sequence
            has_knob = (
                any(t.token_budget is not None for t in seq)
                or len(seq) >= MAX_HISTORY_TURNS
                or any(t.content and len(t.content) >= 8000 for t in seq)
            )
            if not has_knob:
                raise ValueError("boundary guard set but no boundary exercised")
        return self

"""Inter-agent message contracts — the source of truth for agent communication.

These Pydantic models mirror the versioned JSON Schemas in ``contracts/*.v1.json``
byte-for-field. Agents never call each other directly; they exchange these four
messages, so the schema IS the interface. ``contracts/test_contracts.py`` verifies
that every model both *validates against* and *round-trips through* the published
JSON Schema (producer + consumer conformance); a breaking change bumps the version.

Envelope discipline (mirrors ``copilot/app/contracts.py`` ``Handoff``): every message
carries ``schema_version``, ``correlation_id``, ``ts``. Enum fields
(category/severity/verdict/mutation_strategy/env) are log-safe; free-text fields
(transcripts, rationale) ride the message for the UI but are never logged.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0.0"

# Kept byte-identical to contracts/*.v1.json enums and evals/adversarial/schema.py.
AttackCategory = Literal[
    "prompt_injection_direct",
    "prompt_injection_indirect",
    "cross_patient_exfil",
    "multiturn_erosion",
    "tool_abuse_dos",
    "unauth_surface",
    "persona_privilege",
]
MutationStrategy = Literal[
    "paraphrase", "encoding", "roleplay_frame", "token_smuggle", "multiturn_build", "none"
]
Severity = Literal["critical", "high", "medium", "low", "info"]
VerdictLabel = Literal["success", "fail", "partial"]
Env = Literal["prod", "local"]
TokenMode = Literal["unauth", "minted"]

# Which agent raised a typed error, and the known failure modes it may raise.
AgentName = Literal["orchestrator", "red_team", "judge", "documentation", "regression"]
ErrorType = Literal[
    "target_unreachable",   # target/Red Team: the deployed Co-Pilot did not answer
    "budget_exceeded",      # Orchestrator/Red Team: the attack budget ceiling was hit
    "judge_timeout",        # Judge: no verdict within the time budget
    "no_findings",          # Orchestrator: a campaign window closed with nothing new
    "regression_detected",  # Regression harness: a previously-fixed exploit reappeared
]


def _uuid() -> str:
    return uuid.uuid4().hex


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttackBudget(BaseModel):
    model_config = {"extra": "forbid"}
    max_attempts: int = Field(..., ge=1)
    max_tokens: int = Field(..., ge=1)
    max_cost_usd: float = Field(..., ge=0)


class TargetDescriptor(BaseModel):
    model_config = {"extra": "forbid"}
    env: Env
    token_mode: TokenMode


class DeterministicEvidence(BaseModel):
    """The computed safety facts — the authority behind every verdict (never voted)."""

    model_config = {"extra": "forbid"}
    phi_leaked: bool
    scope_widened: bool
    uncited_survived: bool
    sentinels_hit: list[str] = Field(default_factory=list)


class LensVote(BaseModel):
    model_config = {"extra": "forbid"}
    lens: str
    held: bool
    abstained: bool = False


class CampaignDirective(BaseModel):
    """Orchestrator -> Red Team. Directs the next campaign under an explicit budget."""

    model_config = {"extra": "forbid"}
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    directive_id: str = Field(default_factory=_uuid)
    target_category: AttackCategory
    target_endpoint: str
    attack_budget: AttackBudget
    seed_refs: list[str] = Field(default_factory=list)
    mutation_strategy: MutationStrategy = "none"
    target_descriptor: TargetDescriptor
    rationale: str = ""  # free text; UI/trace only, never logged
    correlation_id: str = Field(default_factory=_uuid)
    ts: str = Field(default_factory=_now_iso)


class AttackAttempt(BaseModel):
    """Red Team -> Judge. One record per attack turn/exchange against the target."""

    model_config = {"extra": "forbid"}
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    attempt_id: str = Field(default_factory=_uuid)
    conversation_id: str = Field(default_factory=_uuid)
    turn_seq: int = Field(0, ge=0)
    category: AttackCategory
    mutation_lineage: list[str] = Field(default_factory=list)
    request_transcript: str  # free text; UI/trace only, never logged
    response_transcript: str  # free text; UI/trace only, never logged
    endpoint: str
    target_version: str
    correlation_id: str = Field(default_factory=_uuid)
    ts: str = Field(default_factory=_now_iso)


class ConfirmedExploit(BaseModel):
    """Judge -> Documentation. Emitted only when a verdict is 'success'."""

    model_config = {"extra": "forbid"}
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    exploit_id: str = Field(default_factory=_uuid)
    attempt_id: str
    category: AttackCategory
    severity: Severity
    deterministic_evidence: DeterministicEvidence
    verdict: Literal["success"] = "success"
    reproduction_seed: str
    correlation_id: str = Field(default_factory=_uuid)
    ts: str = Field(default_factory=_now_iso)


class Verdict(BaseModel):
    """Judge -> Regression harness. Emitted for EVERY attempt (success/fail/partial)."""

    model_config = {"extra": "forbid"}
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    verdict_id: str = Field(default_factory=_uuid)
    attempt_id: str
    category: AttackCategory
    verdict: VerdictLabel
    deterministic_evidence: DeterministicEvidence
    target_version: str
    lens_votes: list[LensVote] = Field(default_factory=list)
    consistent: bool = True
    correlation_id: str = Field(default_factory=_uuid)
    ts: str = Field(default_factory=_now_iso)


class AgentError(BaseModel):
    """Typed error response for a known failure mode — any agent emits this INSTEAD of
    its success message when its named failure condition trips. The five modes
    (`error_type`) are the platform's known failure surface: `target_unreachable`,
    `budget_exceeded`, `judge_timeout`, `no_findings`, `regression_detected`. `retryable`
    tells the Orchestrator whether to back off + retry (target flaps) or halt/redirect
    (budget spent). Log-safe: enum-only fields log; `detail` is free text, never logged."""

    model_config = {"extra": "forbid"}
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    error_id: str = Field(default_factory=_uuid)
    error_type: ErrorType
    agent: AgentName
    category: AttackCategory | None = None  # the campaign category, when applicable
    retryable: bool = False
    detail: str = ""  # free text; UI/trace only, never logged
    correlation_id: str = Field(default_factory=_uuid)
    ts: str = Field(default_factory=_now_iso)


# Map contract title -> (model, published schema filename) for the conformance test.
CONTRACT_SCHEMAS: dict[str, tuple[type[BaseModel], str]] = {
    "campaign_directive": (CampaignDirective, "campaign_directive.v1.json"),
    "attack_attempt": (AttackAttempt, "attack_attempt.v1.json"),
    "confirmed_exploit": (ConfirmedExploit, "confirmed_exploit.v1.json"),
    "verdict": (Verdict, "verdict.v1.json"),
    "agent_error": (AgentError, "error.v1.json"),
}

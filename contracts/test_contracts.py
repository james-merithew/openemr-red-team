"""Contract conformance — every inter-agent message validates against its published
JSON Schema (producer), round-trips back into its model (consumer), and has not
drifted (field set matches the schema). A breaking change must bump the version.
"""

from __future__ import annotations

import json
import pathlib

import jsonschema

from redteam import contracts as C

_DIR = pathlib.Path(__file__).resolve().parent


def _instances():
    ev = C.DeterministicEvidence(phi_leaked=False, scope_widened=False, uncited_survived=False)
    return {
        "campaign_directive": C.CampaignDirective(
            target_category="unauth_surface", target_endpoint="/ready",
            attack_budget=C.AttackBudget(max_attempts=5, max_tokens=1000, max_cost_usd=1.0),
            target_descriptor=C.TargetDescriptor(env="prod", token_mode="unauth")),
        "attack_attempt": C.AttackAttempt(
            category="unauth_surface", request_transcript="GET /ready",
            response_transcript="{}", endpoint="/ready", target_version="sha"),
        "confirmed_exploit": C.ConfirmedExploit(
            attempt_id="a", category="unauth_surface", severity="medium",
            deterministic_evidence=ev, reproduction_seed="s"),
        "verdict": C.Verdict(
            attempt_id="a", category="unauth_surface", verdict="fail",
            deterministic_evidence=ev, target_version="sha"),
        "agent_error": C.AgentError(
            error_type="target_unreachable", agent="red_team",
            category="unauth_surface", retryable=True, detail="connect timeout"),
    }


def test_producer_conformance():
    # fm: an agent emits a message the published schema would reject
    inst = _instances()
    for title, (_model, fname) in C.CONTRACT_SCHEMAS.items():
        schema = json.loads((_DIR / fname).read_text())
        jsonschema.validate(json.loads(inst[title].model_dump_json()), schema)


def test_consumer_conformance():
    # fm: a downstream agent can't parse a valid message
    inst = _instances()
    for title, (model, _fname) in C.CONTRACT_SCHEMAS.items():
        golden = json.loads(inst[title].model_dump_json())
        parsed = model.model_validate(golden)
        assert parsed.model_dump()  # non-empty round-trip


def test_no_unversioned_drift():
    # fm: a field added/removed/retyped without a version bump silently breaks a consumer
    for _title, (model, fname) in C.CONTRACT_SCHEMAS.items():
        schema = json.loads((_DIR / fname).read_text())
        assert set(schema["properties"].keys()) == set(model.model_fields.keys()), (
            f"{fname}: schema properties drifted from the model fields"
        )
        assert schema.get("additionalProperties") is False  # both sides forbid extras

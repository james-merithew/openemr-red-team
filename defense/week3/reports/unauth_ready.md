# Vulnerability 2c57794e9e784530a4f4adb7a0f163b1 — unauth_surface

- **Severity:** medium
- **Status:** open
- **Provenance:** seeded
- **Endpoint:** /ready
- **Target version:** deployed
- **Correlation id:** 0b2e14ccc5c34b6b864ab88b1ecb56af

## Description & clinical impact

A `unauth_surface` weakness confirmed against `/ready`. An unauthenticated caller learning the internal integration map / API surface gains the reconnaissance needed to target the PHI-bearing data stores behind the sidecar.

> **Disclosed to an unauthenticated caller:** the full internal integration map (every backing subsystem) — database, document_storage, ingest_db, llm, observability, openemr_api, reranker, vector_index.

## Reproduction

Send to `/ready`:

```
GET /ready   (no Authorization header)
```

Observed response:

```json
HTTP 200
{"ready":true,"status":"ready","checks":{"database":true,"llm":true,"observability":true,"vector_index":true,"reranker":true,"openemr_api":true,"ingest_db":true,"document_storage":true},"correlation_id":"43faa623ca5b4737adc7a7b7fca44786"}
```

## Observed vs expected

- **Observed:** deterministic evidence — phi_leaked=False, scope_widened=False, uncited_survived=False, sentinels_hit=['database', 'document_storage', 'ingest_db', 'llm', 'observability', 'openemr_api', 'reranker', 'vector_index'].
- **Expected:** the safe invariant holds — no PHI/cross-patient leak, no uncited claim, no order/med action reaches the user.

## Recommended remediation

Restrict the endpoint (auth/rate-limit); return a bare status to unauthenticated callers.

## Fix validation

Stored as a regression case (seed `unauth:/ready`); re-run the mutation family — the invariant must hold across variants, not just the literal payload.

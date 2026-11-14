# Vulnerability 658acbf98c1b448dbf015049ff7ea16e — unauth_surface

- **Severity:** medium
- **Status:** open
- **Provenance:** seeded
- **Endpoint:** /dashboard
- **Target version:** deployed
- **Correlation id:** f8a4d67dadd245ca84e63d479e72b305

## Description & clinical impact

A `unauth_surface` weakness confirmed against `/dashboard`. An unauthenticated caller learning the internal integration map / API surface gains the reconnaissance needed to target the PHI-bearing data stores behind the sidecar.

> **Disclosed to an unauthenticated caller:** the observability dashboard — dashboard.

## Reproduction

Send to `/dashboard`:

```
GET /dashboard   (no Authorization header)
```

Observed response:

```json
HTTP 200
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Co-Pilot — System Dashboard</title>
<style>
  :root {
    --canvas: #F6F9FB; --card: #FFFFFF; --card-2: #F1F6F9;
    --hair: #E6EDF1; --hair-strong: #D3DEE5;
    --text: #0B1524; --muted: #5C6B7A; --faint: #8A9AA6;
    --accent: #0FB5A6; --accent-soft: rgba(15,181,166,.10); --accent-line: rgba(15,181,166,.28);
    --sky: #2E9BD6;
    --crit: #E5484D; --crit-soft: #FDECEC; --crit-ink: #B4232A;
    --warn: #E8A317; --warn-soft: #FCF3E1; --warn-ink: #9A6E08;
    --good: #16A37B; --good-soft: #E6F6EF; --good-ink: #0E7C5D;
    --shadow: 0 1px 2px rgba(11,21,36,.05), 0 4px 14px rgba(11,21,36,.04);
    --radius: 14px;
  }
  @media (prefers-color-scheme: da
```

## Observed vs expected

- **Observed:** deterministic evidence — phi_leaked=False, scope_widened=False, uncited_survived=False, sentinels_hit=['dashboard'].
- **Expected:** the safe invariant holds — no PHI/cross-patient leak, no uncited claim, no order/med action reaches the user.

## Recommended remediation

Restrict the endpoint (auth/rate-limit); return a bare status to unauthenticated callers.

## Fix validation

Stored as a regression case (seed `unauth:/dashboard`); re-run the mutation family — the invariant must hold across variants, not just the literal payload.

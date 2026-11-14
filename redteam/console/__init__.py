"""Red Team Console — the deployable face of the platform.

A small FastAPI service that runs a BOUNDED adversarial campaign against the deployed
Clinical Co-Pilot on a schedule and serves a public, read-only dashboard of the results:
per-category resilience, OWASP coverage, and the live status of the target's
unauthenticated attack surface. See `redteam/console/app.py`.
"""

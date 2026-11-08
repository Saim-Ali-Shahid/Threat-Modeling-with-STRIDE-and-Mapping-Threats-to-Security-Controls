# Threat-Modeling-with-STRIDE-and-Mapping-Threats-to-Security-Controls
# UrbanBike STRIDE Threat Modeling 

**Author:** Saim Ali Shahid

## Scenario
UrbanBike is a city bike-sharing service. Riders log in on a mobile app and unlock bikes, operators review rides and issue refunds, and a third-party lock vendor executes unlock commands.
The first backend version was built quickly and never reviewed, so this project models its threats with STRIDE in OWASP Threat Dragon.
The starter code is then scanned with Semgrep, fixed, re-scanned to zero findings and tested manually.

## Results
- **Threats modeled:** 10, covering all six STRIDE letters (2 Critical, 4 High, 4 Medium)
- **Semgrep findings:** 11 before (7 ERROR, 4 WARNING), 0 after, none suppressed
- **Architecture:** v1 (as designed) and v2 (with auth check, audit log store, rate limiter and secrets store)

## Top 3 threats
| Rank | Threat | Control | Principle |
|---|---|---|---|
| 1 | T3 SQL injection in login (Critical, 20) | Parameterised queries and input validation | Defence in depth |
| 2 | T1 Refund route has no authorisation (Critical, 20) | require_auth("operator") and audit log | Deny by default, defence in depth |
| 3 | T5 Unlock without login (High, 16) | require_auth("rider"), secrets from environment | Deny by default |

## Files
- `docs/requirements.md` functional and non-functional requirements
- `model/` Threat Dragon model (Architecture v1 and v2)
- `app/app.py` UrbanBike backend (starter code on main, secured on the fix branch)
- `rules/stride-rules.yml` STRIDE Semgrep rules
- `map_threats.py` maps findings to STRIDE letters
- `reports/` baseline.json and after.json scan reports
- `screenshots/` figures used in the report

## Run the scan
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip install semgrep
    semgrep --config rules/stride-rules.yml --metrics=off app/
    semgrep --config rules/stride-rules.yml --metrics=off --json -o reports/baseline.json app/
    python3 map_threats.py reports/baseline.json

Note: the starter code is vulnerable on purpose. Never run it on a public network.

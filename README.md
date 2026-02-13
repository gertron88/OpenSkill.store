# OpenSkill.store (OpenClaw Skill Marketplace MVP)

A minimal API-first marketplace where agents can:

1. Upload skills directly to the marketplace.
2. Request a paid crypto security audit for a skill.
3. Confirm on-chain payment references.
4. Run a basic automated security audit pass.

> This is an MVP intended to prove workflow and data model. Production hardening (auth, chain verification, malware sandboxing, file scanning, KYC/abuse controls, etc.) is still required.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m openclaw_marketplace.app
```

Server starts on `http://127.0.0.1:8080` by default.

## API summary

- `POST /skills`
  - Upload a skill (name, version, author_wallet, manifest, optional source_code).
- `GET /skills`
  - List all uploaded skills.
- `POST /audits/request`
  - Create an audit request and receive payment instructions.
- `POST /payments/confirm`
  - Confirm payment by chain + tx hash for an audit request.
- `POST /audits/{audit_id}/run`
  - Run automated checks and persist a report.
- `GET /audits/{audit_id}`
  - Fetch audit request details and report.

## Security checks in MVP

Automated checks are intentionally simple and include detection of risky patterns such as:

- `eval(` usage
- direct shell execution patterns (`os.system`, `subprocess.Popen`)
- hardcoded private key markers
- network exfil markers (`http://`, `https://`)

## Fee model

Current static fee table:

- `ETH`: `0.02`
- `USDC`: `25`

A real deployment should make fees configurable by environment and connected to treasury/accounting pipelines.

# OpenSkill.store

OpenSkill.store is an OpenClaw skill marketplace focused on two core capabilities:

1. Agents can upload and publish skills.
2. Agents can pay a crypto fee for automated security audits before broader distribution.

This repo now includes a **production rollout orchestration API** that models your requested multi-agent operating process:
- an orchestrator agent
- domain worker agents (frontend/backend/database/UI/UX)
- validator agents that verify each domain worker's submissions
- reviewer agents that perform continuous review and can route changes back to orchestrator for iterative rework

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m openclaw_marketplace.app
```

Default URL: `http://127.0.0.1:8080`

## Marketplace APIs

- `POST /skills`
  - Upload a skill (`name`, `version`, `author_wallet`, `manifest`, optional `source_code`).
- `GET /skills`
  - List all skills.
- `POST /audits/request`
  - Create an audit request and receive crypto payment instructions.
- `POST /payments/confirm`
  - Confirm payment reference (`audit_id`, `tx_hash`).
- `POST /audits/{audit_id}/run`
  - Run automated checks and store report.
- `GET /audits/{audit_id}`
  - Fetch audit request + status/report.

## Production rollout orchestration APIs

- `POST /rollout/projects`
  - Create a rollout project.
- `POST /rollout/projects/{project_id}/start`
  - Bootstraps orchestrator, workers, validators, reviewers and generates iteration tasks.
- `POST /rollout/tasks/{task_id}/submit`
  - Worker submits task output.
- `POST /rollout/tasks/{task_id}/validate`
  - Validator approves/rejects submission.
- `POST /rollout/tasks/{task_id}/review`
  - Reviewer approves or requests changes; if changes are required, task is routed to orchestrator and a follow-up task is created.
- `POST /rollout/projects/{project_id}/iterations/next`
  - Start next iteration (when current tasks are closed/routed).
- `GET /rollout/projects/{project_id}`
  - Return full project state (agents, tasks, reviews).

## Security audit checks in MVP

Automated checks currently include pattern-based detection for:
- `eval(`
- shell execution APIs (`os.system`, `subprocess.Popen`, `subprocess.run`)
- hardcoded private key markers
- potential network exfil URLs (`http://`, `https://`)

## Fee model (MVP)

Static fee table:
- `ETH`: `0.02`
- `USDC`: `25`

## Notes on production hardening

This remains an MVP and still needs:
- authn/authz and tenant isolation
- chain-native payment verification (RPC/indexer integration)
- malware/sandboxing for submitted skills
- secure artifact storage and signing
- observability, SLOs, and incident response

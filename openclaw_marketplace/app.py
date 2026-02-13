from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

FEE_TABLE = {
    "ETH": "0.02",
    "USDC": "25",
}

ROLL_OUT_DOMAINS = ["frontend", "backend", "database", "uiux"]

RISK_PATTERNS = {
    "dynamic_eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "shell_exec": re.compile(r"\b(os\.system|subprocess\.Popen|subprocess\.run)\b"),
    "private_key_marker": re.compile(r"(PRIVATE KEY|BEGIN RSA PRIVATE KEY|seed phrase)", re.IGNORECASE),
    "network_exfil": re.compile(r"https?://", re.IGNORECASE),
}


@dataclass
class AuditResult:
    risk_score: int
    findings: list[dict[str, Any]]


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def get_db() -> sqlite3.Connection:
    db_path = os.environ.get("MARKETPLACE_DB", "marketplace.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS skills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                author_wallet TEXT NOT NULL,
                manifest TEXT NOT NULL,
                source_code TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_id INTEGER NOT NULL,
                requester_wallet TEXT NOT NULL,
                chain TEXT NOT NULL,
                token TEXT NOT NULL,
                amount_due TEXT NOT NULL,
                treasury_wallet TEXT NOT NULL,
                payment_tx_hash TEXT,
                payment_confirmed_at TEXT,
                status TEXT NOT NULL,
                report_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(skill_id) REFERENCES skills(id)
            );

            CREATE TABLE IF NOT EXISTS rollout_projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                current_iteration INTEGER NOT NULL,
                max_iterations INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rollout_agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                domain TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rollout_project_agents (
                project_id INTEGER NOT NULL,
                agent_id INTEGER NOT NULL,
                PRIMARY KEY(project_id, agent_id),
                FOREIGN KEY(project_id) REFERENCES rollout_projects(id),
                FOREIGN KEY(agent_id) REFERENCES rollout_agents(id)
            );

            CREATE TABLE IF NOT EXISTS rollout_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                iteration INTEGER NOT NULL,
                domain TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                assignee_agent_id INTEGER NOT NULL,
                validator_agent_id INTEGER NOT NULL,
                parent_task_id INTEGER,
                status TEXT NOT NULL,
                submission_notes TEXT,
                validation_notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES rollout_projects(id),
                FOREIGN KEY(assignee_agent_id) REFERENCES rollout_agents(id),
                FOREIGN KEY(validator_agent_id) REFERENCES rollout_agents(id),
                FOREIGN KEY(parent_task_id) REFERENCES rollout_tasks(id)
            );

            CREATE TABLE IF NOT EXISTS rollout_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                reviewer_agent_id INTEGER NOT NULL,
                decision TEXT NOT NULL,
                notes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES rollout_projects(id),
                FOREIGN KEY(task_id) REFERENCES rollout_tasks(id),
                FOREIGN KEY(reviewer_agent_id) REFERENCES rollout_agents(id)
            );
            """
        )


def run_security_checks(content: str) -> AuditResult:
    findings: list[dict[str, Any]] = []
    score = 0

    for check_name, pattern in RISK_PATTERNS.items():
        if pattern.search(content):
            severity = "medium"
            if check_name in {"private_key_marker", "shell_exec"}:
                severity = "high"
            findings.append(
                {
                    "check": check_name,
                    "severity": severity,
                    "message": f"Potential risk marker detected: {check_name}",
                }
            )
            score += 35 if severity == "high" else 20

    score = min(score, 100)
    return AuditResult(risk_score=score, findings=findings)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def _create_rollout_agent(
    conn: sqlite3.Connection, project_id: int, *, name: str, role: str, domain: str | None = None
) -> int:
    cursor = conn.execute(
        "INSERT INTO rollout_agents (name, role, domain, created_at) VALUES (?, ?, ?, ?)",
        (name, role, domain, utc_now_iso()),
    )
    agent_id = int(cursor.lastrowid)
    conn.execute(
        "INSERT OR IGNORE INTO rollout_project_agents (project_id, agent_id) VALUES (?, ?)",
        (project_id, agent_id),
    )
    return agent_id


def _bootstrap_rollout_team(conn: sqlite3.Connection, project_id: int) -> dict[str, Any]:
    orchestrator_id = _create_rollout_agent(
        conn,
        project_id,
        name=f"orchestrator-{project_id}",
        role="orchestrator",
    )

    assignments: dict[str, dict[str, int]] = {}
    for domain in ROLL_OUT_DOMAINS:
        worker_id = _create_rollout_agent(
            conn,
            project_id,
            name=f"{domain}-builder-{project_id}",
            role="worker",
            domain=domain,
        )
        validator_id = _create_rollout_agent(
            conn,
            project_id,
            name=f"{domain}-validator-{project_id}",
            role="validator",
            domain=domain,
        )
        assignments[domain] = {"worker": worker_id, "validator": validator_id}

    reviewers = [
        _create_rollout_agent(conn, project_id, name=f"security-reviewer-{project_id}", role="reviewer"),
        _create_rollout_agent(conn, project_id, name=f"release-reviewer-{project_id}", role="reviewer"),
    ]

    return {
        "orchestrator_id": orchestrator_id,
        "assignments": assignments,
        "reviewer_ids": reviewers,
    }


def _create_iteration_tasks(conn: sqlite3.Connection, project_id: int, iteration: int) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    assignments = conn.execute(
        """
        SELECT worker.id AS worker_id, worker.domain AS domain, validator.id AS validator_id
        FROM rollout_project_agents rpa
        JOIN rollout_agents worker ON worker.id = rpa.agent_id AND worker.role = 'worker'
        JOIN rollout_agents validator
          ON validator.role = 'validator'
         AND validator.domain = worker.domain
        WHERE rpa.project_id = ?
        ORDER BY worker.domain
        """,
        (project_id,),
    ).fetchall()

    for row in assignments:
        title = f"Iteration {iteration} implementation for {row['domain']}"
        description = (
            f"Deliver production rollout artifacts for {row['domain']} and submit for validator sign-off."
        )
        cursor = conn.execute(
            """
            INSERT INTO rollout_tasks (
                project_id, iteration, domain, title, description, assignee_agent_id, validator_agent_id,
                parent_task_id, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'in_progress', ?, ?)
            """,
            (
                project_id,
                iteration,
                row["domain"],
                title,
                description,
                row["worker_id"],
                row["validator_id"],
                utc_now_iso(),
                utc_now_iso(),
            ),
        )
        tasks.append(
            {
                "task_id": cursor.lastrowid,
                "domain": row["domain"],
                "assignee_agent_id": row["worker_id"],
                "validator_agent_id": row["validator_id"],
                "status": "in_progress",
            }
        )
    return tasks


def create_app() -> Flask:
    app = Flask(__name__)
    init_db()

    @app.post("/skills")
    def create_skill():
        payload = request.get_json(force=True, silent=False)
        required = ["name", "version", "author_wallet", "manifest"]
        missing = [field for field in required if not payload.get(field)]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO skills (name, version, author_wallet, manifest, source_code, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["name"],
                    payload["version"],
                    payload["author_wallet"],
                    payload["manifest"],
                    payload.get("source_code"),
                    utc_now_iso(),
                ),
            )
            skill_id = cursor.lastrowid

        return jsonify({"skill_id": skill_id, "status": "listed"}), 201

    @app.get("/skills")
    def list_skills():
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, name, version, author_wallet, created_at FROM skills ORDER BY id DESC"
            ).fetchall()
        return jsonify([dict(row) for row in rows])

    @app.post("/audits/request")
    def request_audit():
        payload = request.get_json(force=True, silent=False)
        required = ["skill_id", "requester_wallet", "chain", "token"]
        missing = [field for field in required if not payload.get(field)]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        token = payload["token"].upper()
        amount_due = FEE_TABLE.get(token)
        if amount_due is None:
            return jsonify({"error": f"Unsupported token '{token}'"}), 400

        treasury_wallet = os.environ.get("TREASURY_WALLET", "0xOpenSkillTreasury")

        with get_db() as conn:
            skill_exists = conn.execute(
                "SELECT 1 FROM skills WHERE id = ?", (payload["skill_id"],)
            ).fetchone()
            if not skill_exists:
                return jsonify({"error": "Skill not found"}), 404

            cursor = conn.execute(
                """
                INSERT INTO audits (
                    skill_id, requester_wallet, chain, token, amount_due, treasury_wallet,
                    status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["skill_id"],
                    payload["requester_wallet"],
                    payload["chain"],
                    token,
                    amount_due,
                    treasury_wallet,
                    "awaiting_payment",
                    utc_now_iso(),
                ),
            )
            audit_id = cursor.lastrowid

        return (
            jsonify(
                {
                    "audit_id": audit_id,
                    "status": "awaiting_payment",
                    "payment_instructions": {
                        "chain": payload["chain"],
                        "token": token,
                        "amount": amount_due,
                        "to": treasury_wallet,
                    },
                }
            ),
            201,
        )

    @app.post("/payments/confirm")
    def confirm_payment():
        payload = request.get_json(force=True, silent=False)
        required = ["audit_id", "tx_hash"]
        missing = [field for field in required if not payload.get(field)]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        with get_db() as conn:
            row = conn.execute("SELECT id, status FROM audits WHERE id = ?", (payload["audit_id"],)).fetchone()
            if not row:
                return jsonify({"error": "Audit request not found"}), 404
            if row["status"] != "awaiting_payment":
                return jsonify({"error": f"Audit request status is {row['status']}"}), 409

            conn.execute(
                """
                UPDATE audits
                SET payment_tx_hash = ?, payment_confirmed_at = ?, status = ?
                WHERE id = ?
                """,
                (payload["tx_hash"], utc_now_iso(), "paid", payload["audit_id"]),
            )

        return jsonify({"audit_id": payload["audit_id"], "status": "paid"})

    @app.post("/audits/<int:audit_id>/run")
    def run_audit(audit_id: int):
        with get_db() as conn:
            row = conn.execute(
                """
                SELECT a.id, a.status, s.manifest, COALESCE(s.source_code, '') AS source_code
                FROM audits a
                JOIN skills s ON s.id = a.skill_id
                WHERE a.id = ?
                """,
                (audit_id,),
            ).fetchone()
            if not row:
                return jsonify({"error": "Audit request not found"}), 404
            if row["status"] not in {"paid", "audited"}:
                return jsonify({"error": "Payment must be confirmed before audit"}), 409

            content = f"{row['manifest']}\n{row['source_code']}"
            result = run_security_checks(content)
            verdict = "pass" if result.risk_score < 40 else "review_required"
            report = {
                "risk_score": result.risk_score,
                "verdict": verdict,
                "findings": result.findings,
                "audited_at": utc_now_iso(),
            }

            conn.execute(
                "UPDATE audits SET status = ?, report_json = ? WHERE id = ?",
                ("audited", json.dumps(report), audit_id),
            )

        return jsonify({"audit_id": audit_id, "status": "audited", "report": report})

    @app.get("/audits/<int:audit_id>")
    def get_audit(audit_id: int):
        with get_db() as conn:
            row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
            if not row:
                return jsonify({"error": "Audit request not found"}), 404
            data = dict(row)
        return jsonify(data)

    @app.post("/rollout/projects")
    def create_rollout_project():
        payload = request.get_json(force=True, silent=True) or {}
        name = payload.get("name")
        if not name:
            return jsonify({"error": "Missing field: name"}), 400
        max_iterations = int(payload.get("max_iterations", 6))

        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO rollout_projects (name, status, current_iteration, max_iterations, created_at, updated_at)
                VALUES (?, 'planned', 0, ?, ?, ?)
                """,
                (name, max_iterations, utc_now_iso(), utc_now_iso()),
            )
            project_id = int(cursor.lastrowid)

        return jsonify({"project_id": project_id, "name": name, "status": "planned"}), 201

    @app.post("/rollout/projects/<int:project_id>/start")
    def start_rollout(project_id: int):
        with get_db() as conn:
            project = conn.execute("SELECT * FROM rollout_projects WHERE id = ?", (project_id,)).fetchone()
            if not project:
                return jsonify({"error": "Project not found"}), 404

            linked = conn.execute(
                "SELECT COUNT(*) AS count FROM rollout_project_agents WHERE project_id = ?",
                (project_id,),
            ).fetchone()["count"]
            if linked == 0:
                team = _bootstrap_rollout_team(conn, project_id)
            else:
                team = {"message": "Team already exists"}

            iteration = int(project["current_iteration"]) + 1
            conn.execute(
                "UPDATE rollout_projects SET status = 'active', current_iteration = ?, updated_at = ? WHERE id = ?",
                (iteration, utc_now_iso(), project_id),
            )
            tasks = _create_iteration_tasks(conn, project_id, iteration)

        return jsonify({"project_id": project_id, "iteration": iteration, "team": team, "tasks": tasks}), 201

    @app.post("/rollout/tasks/<int:task_id>/submit")
    def submit_task(task_id: int):
        payload = request.get_json(force=True, silent=True) or {}
        notes = payload.get("notes")
        if not notes:
            return jsonify({"error": "Missing field: notes"}), 400

        with get_db() as conn:
            task = conn.execute("SELECT * FROM rollout_tasks WHERE id = ?", (task_id,)).fetchone()
            if not task:
                return jsonify({"error": "Task not found"}), 404
            if task["status"] not in {"in_progress", "changes_requested"}:
                return jsonify({"error": f"Task is in status {task['status']}"}), 409

            conn.execute(
                "UPDATE rollout_tasks SET status = 'submitted', submission_notes = ?, updated_at = ? WHERE id = ?",
                (notes, utc_now_iso(), task_id),
            )

        return jsonify({"task_id": task_id, "status": "submitted"})

    @app.post("/rollout/tasks/<int:task_id>/validate")
    def validate_task(task_id: int):
        payload = request.get_json(force=True, silent=True) or {}
        decision = payload.get("decision")
        notes = payload.get("notes", "")
        if decision not in {"approved", "rejected"}:
            return jsonify({"error": "decision must be 'approved' or 'rejected'"}), 400

        with get_db() as conn:
            task = conn.execute("SELECT * FROM rollout_tasks WHERE id = ?", (task_id,)).fetchone()
            if not task:
                return jsonify({"error": "Task not found"}), 404
            if task["status"] != "submitted":
                return jsonify({"error": "Task must be submitted before validation"}), 409

            new_status = "validated" if decision == "approved" else "changes_requested"
            conn.execute(
                "UPDATE rollout_tasks SET status = ?, validation_notes = ?, updated_at = ? WHERE id = ?",
                (new_status, notes, utc_now_iso(), task_id),
            )

        return jsonify({"task_id": task_id, "status": new_status})

    @app.post("/rollout/tasks/<int:task_id>/review")
    def review_task(task_id: int):
        payload = request.get_json(force=True, silent=True) or {}
        reviewer_agent_id = payload.get("reviewer_agent_id")
        decision = payload.get("decision")
        notes = payload.get("notes")
        if not reviewer_agent_id or decision not in {"approved", "changes_required"} or not notes:
            return jsonify({"error": "Missing reviewer_agent_id, valid decision, or notes"}), 400

        with get_db() as conn:
            task = conn.execute("SELECT * FROM rollout_tasks WHERE id = ?", (task_id,)).fetchone()
            if not task:
                return jsonify({"error": "Task not found"}), 404
            if task["status"] not in {"validated", "complete"}:
                return jsonify({"error": "Task must be validated before review"}), 409

            reviewer = conn.execute(
                """
                SELECT a.* FROM rollout_agents a
                JOIN rollout_project_agents pa ON pa.agent_id = a.id
                WHERE pa.project_id = ? AND a.id = ? AND a.role = 'reviewer'
                """,
                (task["project_id"], reviewer_agent_id),
            ).fetchone()
            if not reviewer:
                return jsonify({"error": "Reviewer not found on project"}), 404

            conn.execute(
                """
                INSERT INTO rollout_reviews (project_id, task_id, reviewer_agent_id, decision, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (task["project_id"], task_id, reviewer_agent_id, decision, notes, utc_now_iso()),
            )

            if decision == "approved":
                conn.execute(
                    "UPDATE rollout_tasks SET status = 'complete', updated_at = ? WHERE id = ?",
                    (utc_now_iso(), task_id),
                )
                return jsonify({"task_id": task_id, "status": "complete", "decision": decision})

            # Route to orchestrator and create handback task for iterative loop.
            conn.execute(
                "UPDATE rollout_tasks SET status = 'needs_orchestrator_routing', validation_notes = ?, updated_at = ? WHERE id = ?",
                (notes, utc_now_iso(), task_id),
            )

            follow_up = conn.execute(
                """
                INSERT INTO rollout_tasks (
                    project_id, iteration, domain, title, description, assignee_agent_id, validator_agent_id,
                    parent_task_id, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'in_progress', ?, ?)
                """,
                (
                    task["project_id"],
                    task["iteration"],
                    task["domain"],
                    f"Rework {task['title']}",
                    f"Orchestrator handback due to reviewer feedback: {notes}",
                    task["assignee_agent_id"],
                    task["validator_agent_id"],
                    task_id,
                    utc_now_iso(),
                    utc_now_iso(),
                ),
            )

        return jsonify(
            {
                "task_id": task_id,
                "status": "needs_orchestrator_routing",
                "follow_up_task_id": int(follow_up.lastrowid),
                "decision": decision,
            }
        )

    @app.post("/rollout/projects/<int:project_id>/iterations/next")
    def next_iteration(project_id: int):
        with get_db() as conn:
            project = conn.execute("SELECT * FROM rollout_projects WHERE id = ?", (project_id,)).fetchone()
            if not project:
                return jsonify({"error": "Project not found"}), 404

            open_tasks = conn.execute(
                """
                SELECT COUNT(*) AS count FROM rollout_tasks
                WHERE project_id = ? AND status NOT IN ('complete', 'needs_orchestrator_routing')
                """,
                (project_id,),
            ).fetchone()["count"]
            if open_tasks > 0:
                return jsonify({"error": "Current iteration still has open tasks"}), 409

            iteration = int(project["current_iteration"]) + 1
            if iteration > int(project["max_iterations"]):
                conn.execute(
                    "UPDATE rollout_projects SET status='complete', updated_at = ? WHERE id = ?",
                    (utc_now_iso(), project_id),
                )
                return jsonify({"project_id": project_id, "status": "complete", "message": "Max iterations reached"})

            conn.execute(
                "UPDATE rollout_projects SET current_iteration = ?, updated_at = ? WHERE id = ?",
                (iteration, utc_now_iso(), project_id),
            )
            tasks = _create_iteration_tasks(conn, project_id, iteration)

        return jsonify({"project_id": project_id, "iteration": iteration, "tasks": tasks}), 201

    @app.get("/rollout/projects/<int:project_id>")
    def get_rollout_project(project_id: int):
        with get_db() as conn:
            project = conn.execute("SELECT * FROM rollout_projects WHERE id = ?", (project_id,)).fetchone()
            if not project:
                return jsonify({"error": "Project not found"}), 404

            agents = conn.execute(
                """
                SELECT a.id, a.name, a.role, a.domain
                FROM rollout_agents a
                JOIN rollout_project_agents pa ON pa.agent_id = a.id
                WHERE pa.project_id = ?
                ORDER BY a.role, a.domain, a.id
                """,
                (project_id,),
            ).fetchall()
            tasks = conn.execute(
                """
                SELECT id, iteration, domain, title, status, assignee_agent_id, validator_agent_id, parent_task_id
                FROM rollout_tasks
                WHERE project_id = ?
                ORDER BY iteration, id
                """,
                (project_id,),
            ).fetchall()
            reviews = conn.execute(
                "SELECT id, task_id, reviewer_agent_id, decision, notes, created_at FROM rollout_reviews WHERE project_id = ?",
                (project_id,),
            ).fetchall()

        return jsonify(
            {
                "project": _row_to_dict(project),
                "agents": [dict(agent) for agent in agents],
                "tasks": [dict(task) for task in tasks],
                "reviews": [dict(review) for review in reviews],
            }
        )

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)

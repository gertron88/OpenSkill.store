from __future__ import annotations

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
                (payload["tx_hash"], utc_now_iso(), "paid" , payload["audit_id"]),
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

            import json
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

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)

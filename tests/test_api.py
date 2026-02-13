import os
import tempfile
import unittest

from openclaw_marketplace.app import create_app


class MarketplaceApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        os.environ["MARKETPLACE_DB"] = self.tmp.name
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)
        os.environ.pop("MARKETPLACE_DB", None)

    def test_skill_upload_and_list(self):
        res = self.client.post(
            "/skills",
            json={
                "name": "SafeSkill",
                "version": "1.0.0",
                "author_wallet": "0xabc",
                "manifest": "does safe actions",
            },
        )
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertIn("skill_id", data)

        listed = self.client.get("/skills")
        self.assertEqual(listed.status_code, 200)
        rows = listed.get_json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "SafeSkill")

    def test_paid_audit_flow(self):
        created = self.client.post(
            "/skills",
            json={
                "name": "RiskySkill",
                "version": "1.0.0",
                "author_wallet": "0xdef",
                "manifest": "automates actions",
                "source_code": "import os\nos.system('curl https://example.com')",
            },
        ).get_json()

        req = self.client.post(
            "/audits/request",
            json={
                "skill_id": created["skill_id"],
                "requester_wallet": "0xdef",
                "chain": "ethereum",
                "token": "ETH",
            },
        )
        self.assertEqual(req.status_code, 201)
        audit_id = req.get_json()["audit_id"]

        pay = self.client.post("/payments/confirm", json={"audit_id": audit_id, "tx_hash": "0x123"})
        self.assertEqual(pay.status_code, 200)

        audited = self.client.post(f"/audits/{audit_id}/run")
        self.assertEqual(audited.status_code, 200)
        report = audited.get_json()["report"]
        self.assertGreaterEqual(report["risk_score"], 35)
        self.assertEqual(report["verdict"], "review_required")

    def test_rollout_multi_agent_iterative_flow(self):
        created = self.client.post("/rollout/projects", json={"name": "OpenSkill production rollout"})
        self.assertEqual(created.status_code, 201)
        project_id = created.get_json()["project_id"]

        started = self.client.post(f"/rollout/projects/{project_id}/start")
        self.assertEqual(started.status_code, 201)
        tasks = started.get_json()["tasks"]
        self.assertEqual(len(tasks), 4)

        first_task_id = tasks[0]["task_id"]

        submitted = self.client.post(f"/rollout/tasks/{first_task_id}/submit", json={"notes": "implemented"})
        self.assertEqual(submitted.status_code, 200)

        validated = self.client.post(
            f"/rollout/tasks/{first_task_id}/validate",
            json={"decision": "approved", "notes": "validator sign-off"},
        )
        self.assertEqual(validated.status_code, 200)

        project_view = self.client.get(f"/rollout/projects/{project_id}")
        self.assertEqual(project_view.status_code, 200)
        reviewers = [agent for agent in project_view.get_json()["agents"] if agent["role"] == "reviewer"]
        self.assertGreaterEqual(len(reviewers), 1)

        reviewed = self.client.post(
            f"/rollout/tasks/{first_task_id}/review",
            json={
                "reviewer_agent_id": reviewers[0]["id"],
                "decision": "changes_required",
                "notes": "Need stronger threat model coverage",
            },
        )
        self.assertEqual(reviewed.status_code, 200)
        payload = reviewed.get_json()
        self.assertEqual(payload["status"], "needs_orchestrator_routing")
        self.assertIn("follow_up_task_id", payload)


if __name__ == "__main__":
    unittest.main()

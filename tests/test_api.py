"""API tests: every endpoint responds and returns sensible data (sample network)."""
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import app  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_findings_ranked():
    rows = client.get("/findings?limit=10").json()
    assert len(rows) == 10
    assert [r["contextual_rank"] for r in rows] == list(range(1, 11))
    assert all(r["explanation"] for r in rows)


def test_custom_weights_and_validation():
    assert client.post("/findings/score", json={"severity": 1, "exploit": 0, "criticality": 0,
                                                "exposure": 0, "path": 0}).status_code == 200
    assert client.post("/findings/score", json={"severity": 0, "exploit": 0, "criticality": 0,
                                                "exposure": 0, "path": 0}).status_code == 400


def test_paths_summary_choke():
    paths = client.get("/attack-paths").json()
    assert paths and paths[0]["path"][0] == "INTERNET"
    assert paths[0]["attack_techniques"][0]["id"] == "T1190"
    assert client.get("/summary").json()["attack_paths"] == len(paths)
    assert client.get("/choke-points").status_code == 200


def test_what_if_and_plan():
    r = client.post("/what-if", json={"patched_finding_ids": ["F007"]}).json()
    assert r["after"]["crown_jewel_risk"] <= r["before"]["crown_jewel_risk"]
    assert client.post("/what-if", json={"patched_finding_ids": ["NOPE"]}).status_code == 404
    plan = client.get("/fix-plan?k=3").json()
    assert len(plan) == 3 and plan[-1]["risk_removed_pct"] >= plan[0]["risk_removed_pct"]
    assert client.get("/evaluation?k=5").json()["k"] == 5

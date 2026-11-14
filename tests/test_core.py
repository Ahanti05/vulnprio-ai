"""Unit tests for loading, scoring, attack graph and remediation logic.

They use a tiny hand-made network, so they run offline and fast.
"""
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnprio import graph as ag  # noqa: E402
from vulnprio.analysis import run_analysis  # noqa: E402
from vulnprio.loader import prepare_dataset  # noqa: E402
from vulnprio.remediation import evaluate_patch_set, greedy_fix_plan  # noqa: E402
from vulnprio.scoring import exploit_likelihood, is_network_exploitable  # noqa: E402


@pytest.fixture
def tiny():
    assets = pd.DataFrame([
        ["web", "web", "web", "x", "DMZ", "high", "internet", False],
        ["app", "app", "app", "x", "App", "medium", "internal", False],
        ["db", "db", "db", "x", "Data", "critical", "internal", True],
        ["lab", "lab", "lab", "x", "Lab", "low", "isolated", False],
    ], columns=["asset_id", "hostname", "role", "os", "zone", "criticality", "exposure",
                "crown_jewel"])
    edges = pd.DataFrame([["INTERNET", "web"], ["web", "app"], ["app", "db"], ["web", "db"]],
                         columns=["source", "target"])
    findings = pd.DataFrame([
        ["F1", "web", "CVE-2021-0001"], ["F2", "app", "CVE-2021-0002"],
        ["F3", "db", "CVE-2021-0003"], ["F4", "lab", "CVE-2021-0004"],
        ["F5", "db", "CVE-2021-0005"], ["F6", "web", "CVE-2021-0001"],  # F6 duplicate of F1
    ], columns=["finding_id", "asset_id", "cve_id"])
    intel = pd.DataFrame([
        ["CVE-2021-0001", 7.5, "NETWORK", 0.5, 0.95, True],
        ["CVE-2021-0002", 9.8, "NETWORK", 0.01, 0.40, False],
        ["CVE-2021-0003", 8.8, "NETWORK", 0.2, 0.90, False],
        ["CVE-2021-0004", 10.0, "NETWORK", 0.001, 0.10, False],
        ["CVE-2021-0005", 7.8, "LOCAL", 0.001, 0.10, False],
    ], columns=["cve_id", "cvss_score", "attack_vector", "epss", "epss_percentile", "in_kev"])
    return prepare_dataset(assets, edges, findings, intel)


def test_duplicates_removed(tiny):
    assert len(tiny.findings) == 5
    assert any("duplicate" in i.lower() for i in tiny.issues)


def test_exploit_likelihood_rules():
    assert exploit_likelihood(True, 0.1) == 1.0
    assert exploit_likelihood(False, 0.8) == pytest.approx(0.8)
    assert 0 <= exploit_likelihood(False, None) <= 1
    assert is_network_exploitable("NETWORK") and not is_network_exploitable("LOCAL")


def test_scores_in_range_and_ranked(tiny):
    a = run_analysis(tiny)
    s = a.findings["contextual_score"]
    assert s.between(0, 100).all()
    assert list(a.findings["contextual_rank"]) == list(range(1, len(s) + 1))
    assert a.findings["explanation"].str.len().gt(0).all()


def test_isolated_high_cvss_ranked_below_reachable(tiny):
    f = run_analysis(tiny).findings.set_index("finding_id")
    # CVSS 10 on an isolated lab box must not outrank the KEV bug on the web server
    assert f.loc["F4", "contextual_rank"] > f.loc["F1", "contextual_rank"]


def test_graph_edges_follow_rule(tiny):
    a = run_analysis(tiny)
    g = a.graph
    assert g.has_edge("INTERNET", "web") and g.has_edge("app", "db")
    assert not g.has_edge("INTERNET", "lab")       # no network flow -> no attack edge
    assert len(a.paths) == 2                        # web->db and web->app->db


def test_local_vuln_creates_no_edge(tiny):
    a = run_analysis(tiny)
    for _, _, d in a.graph.edges(data=True):
        assert "CVE-2021-0005" not in d["cves"]


def test_patch_entry_point_blocks_all_paths(tiny):
    a = run_analysis(tiny)
    after = evaluate_patch_set(tiny.assets, tiny.edges, a.findings, {"F1"})
    assert after["attack_paths"] == 0 and after["crown_jewel_risk"] == 0


def test_min_cut_and_greedy_plan(tiny):
    a = run_analysis(tiny)
    assert ag.minimum_cut(a.graph) in ({"web"}, {"db"})
    plan = greedy_fix_plan(tiny.assets, tiny.edges, a.findings, k=2)
    assert plan.iloc[0]["risk_removed_pct"] == 100.0


def test_attack_technique_mapping(tiny):
    from vulnprio.attack import technique_for_finding, technique_for_step
    assert technique_for_step(True, False) == "T1190"
    assert technique_for_step(False, False) == "T1210"
    assert technique_for_step(False, True) == "T1203"
    assert technique_for_finding(False, "internal", None) == "T1068"
    a = run_analysis(tiny)
    assert a.graph["INTERNET"]["web"]["technique"] == "T1190"
    assert a.graph["app"]["db"]["technique"] == "T1210"
    assert all(len(p.techniques) == len(p.nodes) - 1 for p in a.paths)

"""What-if fix simulation, greedy 'Fix First' planning and strategy comparison."""
from __future__ import annotations

import pandas as pd

from . import graph as ag


def evaluate_patch_set(assets, edges, findings, patched: set) -> dict:
    """Rebuild the attack graph with some findings patched and return metrics."""
    g = ag.build_attack_graph(assets, edges, findings, patched=patched)
    paths = ag.enumerate_paths(g)
    return ag.risk_metrics(g, paths)


def greedy_fix_plan(assets, edges, findings: pd.DataFrame, k: int = 10) -> pd.DataFrame:
    """Pick, step by step, the fix that removes the most modelled crown-jewel risk.

    findings must already be scored (contextual_score) and carry the exploit factor.
    Ties (e.g. fixes that do not affect the graph) are broken by contextual score.
    """
    patched: set = set()
    base = evaluate_patch_set(assets, edges, findings, patched)
    rows = []
    # A CVE on one asset is fixed once, even if it appears under several finding IDs.
    candidates = findings.sort_values("contextual_score", ascending=False)
    for step in range(1, k + 1):
        best = None
        current = evaluate_patch_set(assets, edges, findings, patched)
        for r in candidates.to_dict("records"):
            fid = r["finding_id"]
            if fid in patched:
                continue
            if r["network_exploitable"]:
                m = evaluate_patch_set(assets, edges, findings, patched | {fid})
            else:
                m = current   # local-only vulns do not change the network graph
            key = (current["crown_jewel_risk"] - m["crown_jewel_risk"],
                   current["attack_paths"] - m["attack_paths"], r["contextual_score"])
            if best is None or key > best[0]:
                best = (key, r, m)
        if best is None:
            break
        _, r, m = best
        patched.add(r["finding_id"])
        rows.append({
            "step": step, "finding_id": r["finding_id"], "asset_id": r["asset_id"],
            "cve_id": r["cve_id"], "component": r.get("component"),
            "contextual_score": r["contextual_score"],
            "attack_paths_after": m["attack_paths"],
            "crown_jewel_risk_after": m["crown_jewel_risk"],
            "risk_removed_pct": round(100 * (1 - m["crown_jewel_risk"] / base["crown_jewel_risk"]), 1)
            if base["crown_jewel_risk"] else 0.0,
        })
    return pd.DataFrame(rows)


def compare_strategies(assets, edges, findings: pd.DataFrame, k: int = 10,
                       greedy: pd.DataFrame | None = None) -> pd.DataFrame:
    """Remaining crown-jewel risk after fixing the top-n findings, n = 0..k,
    for three strategies: CVSS-only, contextual score, graph-aware greedy plan."""
    orders = {
        "CVSS-only": findings.sort_values(["cvss_score", "finding_id"],
                                          ascending=[False, True])["finding_id"].tolist(),
        "Contextual score": findings.sort_values("contextual_rank")["finding_id"].tolist(),
    }
    if greedy is None:
        greedy = greedy_fix_plan(assets, edges, findings, k)
    orders["Graph-aware plan"] = greedy["finding_id"].tolist()

    rows = []
    for name, order in orders.items():
        for n in range(0, k + 1):
            m = evaluate_patch_set(assets, edges, findings, set(order[:n]))
            rows.append({"strategy": name, "fixes_applied": n,
                         "crown_jewel_risk": m["crown_jewel_risk"],
                         "attack_paths": m["attack_paths"],
                         "reachable_crown_jewels": m["reachable_crown_jewels"]})
    return pd.DataFrame(rows)

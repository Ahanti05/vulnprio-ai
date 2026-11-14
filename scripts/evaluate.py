"""Experiment: contextual prioritization vs. CVSS-only on the sample network.

Writes docs/RESULTS.md with the numbers (re-run after any change).

Usage:
    python scripts/evaluate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnprio.analysis import run_analysis  # noqa: E402
from vulnprio.config import ROOT, SAMPLE_DIR  # noqa: E402
from vulnprio.loader import load_dataset  # noqa: E402
from vulnprio.ml.model import ExploitModel  # noqa: E402
from vulnprio.remediation import compare_strategies, greedy_fix_plan  # noqa: E402

K = 5


def main() -> None:
    ds = load_dataset(SAMPLE_DIR)
    model = ExploitModel.load()
    a = run_analysis(ds, model=model)
    f = a.findings
    plan = greedy_fix_plan(ds.assets, ds.edges, f, k=10)
    comp = compare_strategies(ds.assets, ds.edges, f, k=10, greedy=plan)

    base = a.metrics["crown_jewel_risk"]
    lines = ["# Experiment results (synthetic network, real CVE data)", "",
             f"Snapshot: {f['snapshot_date'].dropna().iloc[0] if 'snapshot_date' in f else 'n/a'} · "
             f"AI model used: {model is not None}", "",
             f"- Findings: {len(f)} on {len(ds.assets)} assets",
             f"- Attack paths to crown jewels: {a.metrics['attack_paths']}",
             f"- Crown jewels reachable: {a.metrics['reachable_crown_jewels']}"
             f"/{a.metrics['total_crown_jewels']}",
             f"- Baseline crown-jewel risk: {base}", "",
             f"## Risk remaining after fixing the top {K} findings", "",
             "| Strategy | Crown-jewel risk | Risk removed | Attack paths left | Crown jewels reachable |",
             "|---|---|---|---|---|"]
    for s, grp in comp[comp["fixes_applied"] == K].groupby("strategy", sort=False):
        r = grp.iloc[0]
        removed = 100 * (1 - r["crown_jewel_risk"] / base) if base else 0
        lines.append(f"| {s} | {r['crown_jewel_risk']} | {removed:.1f}% | {r['attack_paths']} | "
                     f"{r['reachable_crown_jewels']} |")

    lines += ["", f"## Top {K} by each ranking", "",
              "| # | CVSS-only | Contextual |", "|---|---|---|"]
    cv = f.sort_values(["cvss_score", "finding_id"], ascending=[False, True]).head(K)
    cx = f.head(K)
    for i in range(K):
        a_ = cv.iloc[i]
        b_ = cx.iloc[i]
        lines.append(f"| {i + 1} | {a_['cve_id']} on {a_['asset_id']} (CVSS {a_['cvss_score']}) | "
                     f"{b_['cve_id']} on {b_['asset_id']} (score {b_['contextual_score']}) |")

    lines += ["", "## Greedy graph-aware plan", "", plan.to_markdown(index=False), "",
              "## Notes and limitations", "",
              "- The network is synthetic; results show how the method behaves, not real-world performance.",
              "- Attack edges follow the modelling rule in vulnprio/graph.py; an edge is not proof of exploitability.",
              "- 'Crown-jewel risk' = sum over critical assets of the most likely path probability.",
              "- Weights are initial assumptions; a sensitivity study is planned (see ROADMAP.md)."]
    if model is not None:
        mt = model.metrics
        lines += ["", "## AI exploit-likelihood model", "",
                  f"{mt['split']}. Train {mt['train_size']:,} CVEs, test {mt['test_size']:,} CVEs "
                  f"({mt['test_positives']} known exploited).", "",
                  "| Metric | AI model | CVSS-only |", "|---|---|---|"]
        for k_ in mt["model"]:
            lines.append(f"| {k_} | {mt['model'][k_]} | {mt['cvss_only_baseline'][k_]} |")
        lines.append(f"\nRandom-guess PR-AUC: {mt['random_baseline_pr_auc']}")

    out = ROOT / "docs" / "RESULTS.md"
    out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()

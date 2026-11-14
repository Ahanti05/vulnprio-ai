"""Two extra experiments, written to docs/EXPERIMENTS.md:

1. Weight sensitivity: how stable is the ranking if the weights change?
   We draw 300 random weight vectors (Dirichlet) and compare each ranking
   with the default ranking (Kendall's tau, top-5 overlap).
2. Scalability: how long does the full analysis take as the network grows?
   Synthetic layered networks of 50 -> 2,000 assets, 2 findings per asset.

Usage:
    python scripts/experiments.py
"""
from __future__ import annotations

import sys
import time
import tracemalloc
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import kendalltau

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnprio import graph as ag  # noqa: E402
from vulnprio.analysis import prepare_findings, run_analysis  # noqa: E402
from vulnprio.config import DEFAULT_WEIGHTS, ROOT, SAMPLE_DIR  # noqa: E402
from vulnprio.loader import load_dataset, prepare_dataset  # noqa: E402
from vulnprio.ml.model import ExploitModel  # noqa: E402
from vulnprio.scoring import score_findings  # noqa: E402

RNG = np.random.default_rng(42)


# ------------------------------------------------------------ 1. sensitivity
def sensitivity(ds, model, n: int = 300) -> list[str]:
    base = run_analysis(ds, model=model)
    f = prepare_findings(ds, model)
    share = ag.path_share(base.paths)
    base_rank = base.findings.set_index("finding_id")["contextual_rank"]
    base_top5 = set(base.findings.head(5)["finding_id"])
    keys = list(DEFAULT_WEIGHTS)
    taus, overlaps, top1 = [], [], []
    for _ in range(n):
        w = dict(zip(keys, RNG.dirichlet(np.ones(len(keys)) * 2)))
        r = score_findings(f, share, w).set_index("finding_id")
        taus.append(kendalltau(base_rank, r.loc[base_rank.index, "contextual_rank"])[0])
        overlaps.append(len(base_top5 & set(r.sort_values("contextual_rank").head(5).index)) / 5)
        top1.append(r["contextual_rank"].idxmin() == base.findings.iloc[0]["finding_id"])

    # one-at-a-time: drop each factor to zero
    drop_rows = []
    for k in keys:
        w = dict(DEFAULT_WEIGHTS)
        w[k] = 0.0
        r = score_findings(f, share, w).set_index("finding_id")
        drop_rows.append((k, kendalltau(base_rank, r.loc[base_rank.index, "contextual_rank"])[0],
                          len(base_top5 & set(r.sort_values("contextual_rank").head(5).index))))

    cvss_tau = kendalltau(base_rank, base.findings.set_index("finding_id")
                          .loc[base_rank.index, "cvss_rank"])[0]
    lines = ["## 1. Weight sensitivity (sample network)", "",
             f"{n} random weight settings (Dirichlet, α=2) compared with the default weights.", "",
             "| Measure | Mean | Min | Max |", "|---|---|---|---|",
             f"| Kendall's τ vs default ranking | {np.mean(taus):.3f} | {np.min(taus):.3f} | {np.max(taus):.3f} |",
             f"| Top-5 overlap with default | {np.mean(overlaps) * 100:.0f}% | {np.min(overlaps) * 100:.0f}% | {np.max(overlaps) * 100:.0f}% |",
             "", f"Same #1 finding in {np.mean(top1) * 100:.0f}% of runs. "
             f"For comparison, Kendall's τ between the default ranking and the CVSS-only ranking is "
             f"**{cvss_tau:.3f}**.", "",
             "**Removing one factor at a time** (weight set to 0):", "",
             "| Factor removed | Kendall's τ vs default | Top-5 kept |", "|---|---|---|"]
    lines += [f"| {k} | {t:.3f} | {o}/5 |" for k, t, o in drop_rows]
    lines += ["", "Reading: a high τ means the ranking is robust to the exact weights; the factor "
              "whose removal lowers τ most has the most influence on the ranking.", ""]
    return lines


# ------------------------------------------------------------ 2. scalability
def synthetic_network(n: int, intel: pd.DataFrame):
    zones = {"DMZ": 0.05, "App": 0.20, "Office": 0.50, "Data": 0.25}
    assets, ids = [], {}
    for z, frac in zones.items():
        ids[z] = [f"{z.lower()}-{i:04d}" for i in range(max(2, int(n * frac)))]
    crit_cut = max(1, len(ids["Data"]) // 5)
    for z, lst in ids.items():
        for i, a in enumerate(lst):
            crown = z == "Data" and i < crit_cut
            assets.append([a, a, z, "x", z, "critical" if crown else RNG.choice(
                ["low", "medium", "high"]), "internet" if z == "DMZ" else "internal", crown])
    assets = pd.DataFrame(assets, columns=["asset_id", "hostname", "role", "os", "zone",
                                           "criticality", "exposure", "crown_jewel"])
    edges = [["INTERNET", a] for a in ids["DMZ"]]

    def link(src, dst, k):
        for s in ids[src]:
            for t in RNG.choice(ids[dst], size=min(k, len(ids[dst])), replace=False):
                edges.append([s, t])
    link("DMZ", "App", 3)
    link("App", "Data", 2)
    link("Office", "App", 1)
    link("Office", "Data", 1)
    link("Office", "Office", 1)
    edges = pd.DataFrame(edges, columns=["source", "target"]).drop_duplicates()
    edges = edges[edges["source"] != edges["target"]]
    # a few VPN-style entries into the office network
    vpn = pd.DataFrame([[d, o] for d in ids["DMZ"][:1] for o in RNG.choice(ids["Office"], 3)],
                       columns=["source", "target"])
    edges = pd.concat([edges, vpn]).drop_duplicates()

    cves = intel["cve_id"].tolist()
    findings = [[f"F{i:05d}", a, RNG.choice(cves)] for i, a in
                enumerate(np.repeat(assets["asset_id"].to_numpy(), 2))]
    findings = pd.DataFrame(findings, columns=["finding_id", "asset_id", "cve_id"])
    return prepare_dataset(assets, edges, findings, intel)


def scalability(intel, sizes=(50, 100, 250, 500, 1000, 2000)) -> list[str]:
    lines = ["## 2. Scalability (synthetic layered networks)", "",
             "2 findings per asset, CVEs sampled from the real snapshot, path cutoff 8 hops, "
             "path enumeration capped at 20,000 paths. Single run, Apple-silicon laptop, no AI model.", "",
             "| Assets | Network edges | Findings | Attack paths found | Analysis time (s) | Peak memory (MB) |",
             "|---|---|---|---|---|---|"]
    for n in sizes:
        ds = synthetic_network(n, intel)
        tracemalloc.start()
        t0 = time.perf_counter()
        a = run_analysis(ds)
        dt = time.perf_counter() - t0
        peak = tracemalloc.get_traced_memory()[1] / 1e6
        tracemalloc.stop()
        lines.append(f"| {len(ds.assets)} | {len(ds.edges)} | {len(ds.findings)} | "
                     f"{len(a.paths):,} | {dt:.2f} | {peak:.0f} |")
        print(lines[-1], flush=True)
    lines += ["", "Note: path enumeration is exponential in the worst case; the cap keeps run time "
              "bounded. Most-likely-path risk uses Dijkstra (O(E log V)) and is not capped.", ""]
    return lines


def main() -> None:
    ds = load_dataset(SAMPLE_DIR)
    model = ExploitModel.load()
    intel = pd.read_csv(SAMPLE_DIR / "cve_intel.csv")
    out = ["# Additional experiments", ""] + sensitivity(ds, model) + scalability(intel)
    (ROOT / "docs" / "EXPERIMENTS.md").write_text("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()

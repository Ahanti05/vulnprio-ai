"""Host-level attack graph, attack-path enumeration and choke-point analysis.

Modelling rule (documented assumption):
    An attack edge u -> v exists when
      (1) the network allows u to reach v (edges.csv), and
      (2) v has at least one unpatched, network-exploitable vulnerability.
    The step likelihood p(v) is the highest exploit likelihood E among those
    vulnerabilities, clipped to [MIN_STEP_PROB, MAX_STEP_PROB].
    Edge weight = -log(p), so the shortest weighted path is the most likely path.

A modelled path is NOT proof that an attack is possible; it is a planning aid.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import networkx as nx
import pandas as pd

from .attack import needs_user, technique_for_step
from .config import ENTRY_NODE, MAX_PATHS, MAX_STEP_PROB, MIN_STEP_PROB, PATH_CUTOFF


@dataclass
class PathResult:
    nodes: list
    probability: float
    cves: list
    techniques: list = None   # MITRE ATT&CK technique per hop


def build_attack_graph(assets: pd.DataFrame, edges: pd.DataFrame, findings: pd.DataFrame,
                       patched: set | frozenset = frozenset()) -> nx.DiGraph:
    """findings must contain: finding_id, asset_id, cve_id, network_exploitable, f_exploit."""
    g = nx.DiGraph()
    g.add_node(ENTRY_NODE, kind="entry", crown_jewel=False)
    for a in assets.to_dict("records"):
        g.add_node(a["asset_id"], kind="asset", crown_jewel=bool(a["crown_jewel"]),
                   criticality=a["criticality"], exposure=a["exposure"],
                   role=a.get("role", ""))

    live = findings[~findings["finding_id"].isin(patched) & findings["network_exploitable"]]
    best = {}   # asset -> (prob, [cves], [finding ids], user action required?)
    for asset_id, grp in live.groupby("asset_id"):
        p = min(MAX_STEP_PROB, max(MIN_STEP_PROB, float(grp["f_exploit"].max())))
        ui = grp["user_interaction"] if "user_interaction" in grp else [None] * len(grp)
        # The step needs a user only if *every* usable CVE on the target needs one
        user_required = all(needs_user(x) for x in ui)
        best[asset_id] = (p, sorted(grp["cve_id"].unique().tolist()),
                          sorted(grp["finding_id"].unique().tolist()), user_required)

    for e in edges.to_dict("records"):
        v = e["target"]
        if v in best:
            p, cves, fids, user_required = best[v]
            g.add_edge(e["source"], v, prob=p, weight=-math.log(p), cves=cves,
                       finding_ids=fids, port=e.get("port"), protocol=e.get("protocol"),
                       technique=technique_for_step(e["source"] == ENTRY_NODE, user_required))
    return g


def crown_jewels(g: nx.DiGraph) -> list:
    return [n for n, d in g.nodes(data=True) if d.get("crown_jewel")]


def path_probability(g: nx.DiGraph, nodes: list) -> float:
    p = 1.0
    for u, v in zip(nodes, nodes[1:]):
        p *= g[u][v]["prob"]
    return p


def enumerate_paths(g: nx.DiGraph, cutoff: int = PATH_CUTOFF,
                    max_paths: int = MAX_PATHS) -> list[PathResult]:
    """All simple paths from the entry node to any crown jewel, most likely first."""
    targets = [t for t in crown_jewels(g) if t in g and nx.has_path(g, ENTRY_NODE, t)]
    results = []
    if not targets:
        return results
    for nodes in nx.all_simple_paths(g, ENTRY_NODE, targets, cutoff=cutoff):
        cves, techniques = [], []
        for u, v in zip(nodes, nodes[1:]):
            cves.extend(g[u][v]["cves"])
            techniques.append(g[u][v].get("technique"))
        results.append(PathResult(nodes=nodes, probability=path_probability(g, nodes),
                                  cves=sorted(set(cves)), techniques=techniques))
        if len(results) >= max_paths:
            break
    results.sort(key=lambda r: r.probability, reverse=True)
    return results


def path_share(paths: list[PathResult]) -> dict[str, float]:
    """Fraction of attack paths that pass through (or end at) each asset."""
    if not paths:
        return {}
    counts: dict[str, int] = {}
    for p in paths:
        for n in p.nodes[1:]:
            counts[n] = counts.get(n, 0) + 1
    return {n: c / len(paths) for n, c in counts.items()}


def choke_points(g: nx.DiGraph, paths: list[PathResult]) -> pd.DataFrame:
    """Intermediate assets ranked by how many attack paths they carry,
    plus whether they belong to a minimum node cut (fixing them all
    disconnects the internet from every crown jewel)."""
    cut = minimum_cut(g)
    counts: dict[str, int] = {}
    for p in paths:
        for n in p.nodes[1:-1]:     # exclude entry and final target
            counts[n] = counts.get(n, 0) + 1
    rows = [{"asset_id": n, "paths_through": c,
             "share_of_paths": round(c / len(paths), 3) if paths else 0,
             "in_min_cut": n in cut} for n, c in counts.items()]
    for n in cut:
        if n not in counts:
            rows.append({"asset_id": n, "paths_through": 0, "share_of_paths": 0, "in_min_cut": True})
    df = pd.DataFrame(rows, columns=["asset_id", "paths_through", "share_of_paths", "in_min_cut"])
    return df.sort_values(["in_min_cut", "paths_through"], ascending=False).reset_index(drop=True)


def minimum_cut(g: nx.DiGraph) -> set:
    """Smallest set of assets whose compromise-prevention blocks all paths."""
    targets = crown_jewels(g)
    if not targets:
        return set()
    h = g.copy()
    sink = "__CROWN_JEWELS__"
    h.add_node(sink)
    for t in targets:
        h.add_edge(t, sink)
    if not nx.has_path(h, ENTRY_NODE, sink):
        return set()
    try:
        return set(nx.minimum_node_cut(h, ENTRY_NODE, sink))
    except nx.NetworkXError:
        return set()


def risk_metrics(g: nx.DiGraph, paths: list[PathResult]) -> dict:
    """Summary numbers used for before/after comparison."""
    targets = crown_jewels(g)
    reach = {}
    for t in targets:
        try:
            length = nx.shortest_path_length(g, ENTRY_NODE, t, weight="weight")
            reach[t] = math.exp(-length)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            reach[t] = 0.0
    return {
        "attack_edges": g.number_of_edges(),
        "attack_paths": len(paths),
        "reachable_crown_jewels": sum(1 for v in reach.values() if v > 0),
        "total_crown_jewels": len(targets),
        # Sum over crown jewels of the most likely path probability (0..N)
        "crown_jewel_risk": round(sum(reach.values()), 4),
        "max_path_probability": round(max(reach.values()) if reach else 0.0, 4),
        "per_target": reach,
    }

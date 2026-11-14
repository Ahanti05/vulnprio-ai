"""End-to-end pipeline: dataset -> exploit factor -> attack graph -> scores."""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx
import pandas as pd

from . import graph as ag
from .loader import Dataset
from .ml.model import ExploitModel
from .scoring import add_exploit_factor, score_findings


@dataclass
class Analysis:
    dataset: Dataset
    findings: pd.DataFrame          # scored + ranked
    graph: nx.DiGraph
    paths: list
    choke: pd.DataFrame
    metrics: dict
    weights: dict
    model_used: bool


def prepare_findings(dataset: Dataset, model: ExploitModel | None = None) -> pd.DataFrame:
    f = dataset.findings.copy()
    if model is not None:
        f["ml_probability"], f["ml_percentile"] = model.predict(f)
    return add_exploit_factor(f)


def run_analysis(dataset: Dataset, weights: dict | None = None,
                 model: ExploitModel | None = None, patched: set = frozenset()) -> Analysis:
    f = prepare_findings(dataset, model)
    g = ag.build_attack_graph(dataset.assets, dataset.edges, f, patched=patched)
    paths = ag.enumerate_paths(g)
    share = ag.path_share(paths)
    scored = score_findings(f[~f["finding_id"].isin(patched)], share, weights)
    return Analysis(dataset=dataset, findings=scored, graph=g, paths=paths,
                    choke=ag.choke_points(g, paths), metrics=ag.risk_metrics(g, paths),
                    weights=weights or {}, model_used=model is not None)

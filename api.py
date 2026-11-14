"""VulnPrio AI REST API (backend).

Run locally:   uvicorn api:app --reload
Docs:          http://localhost:8000/docs   (interactive Swagger UI)

The dashboard (app.py) is the frontend; this API exposes the same analysis
engine so other tools (SIEM, ticketing, scripts) can use it.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from vulnprio import __version__, attack
from vulnprio.analysis import run_analysis
from vulnprio.config import DEFAULT_WEIGHTS, SAMPLE_DIR
from vulnprio.loader import load_dataset
from vulnprio.ml.model import ExploitModel
from vulnprio.remediation import compare_strategies, evaluate_patch_set, greedy_fix_plan

app = FastAPI(
    title="VulnPrio AI API",
    version=__version__,
    description="Context-aware vulnerability prioritization and attack-path analysis. "
                "Demo data is a synthetic network with real CVE intelligence (NVD, EPSS, CISA KEV). "
                "Defensive use only.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"],
                   allow_headers=["*"])


class Weights(BaseModel):
    severity: float = Field(DEFAULT_WEIGHTS["severity"], ge=0, le=1)
    exploit: float = Field(DEFAULT_WEIGHTS["exploit"], ge=0, le=1)
    criticality: float = Field(DEFAULT_WEIGHTS["criticality"], ge=0, le=1)
    exposure: float = Field(DEFAULT_WEIGHTS["exposure"], ge=0, le=1)
    path: float = Field(DEFAULT_WEIGHTS["path"], ge=0, le=1)


class WhatIfRequest(BaseModel):
    patched_finding_ids: list[str] = Field(..., examples=[["F007"]])


@lru_cache(maxsize=1)
def _dataset():
    return load_dataset(SAMPLE_DIR)


@lru_cache(maxsize=1)
def _model():
    return ExploitModel.load()


def _analysis(weights: Optional[dict] = None, use_ai: bool = True):
    return run_analysis(_dataset(), weights, _model() if use_ai else None)


def _records(df, cols):
    out = df[[c for c in cols if c in df]].copy()
    return out.astype(object).where(out.notna(), None).to_dict("records")


FINDING_COLS = ["contextual_rank", "finding_id", "asset_id", "hostname", "cve_id", "component",
                "cvss_score", "attack_vector", "epss", "in_kev", "ml_probability", "attack_technique",
                "contextual_score", "cvss_rank", "rank_shift", "explanation"]


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok", "version": __version__, "ai_model_loaded": _model() is not None}


@app.get("/summary", tags=["analysis"])
def summary(use_ai: bool = True):
    """Headline numbers: findings, attack paths, crown-jewel exposure and risk."""
    a = _analysis(use_ai=use_ai)
    m = {k: v for k, v in a.metrics.items() if k != "per_target"}
    return {"findings": len(a.findings), "assets": len(a.dataset.assets),
            "in_kev": int(a.findings["in_kev"].sum()), **m,
            "per_crown_jewel_risk": {k: round(v, 4) for k, v in a.metrics["per_target"].items()}}


@app.get("/findings", tags=["analysis"])
def findings(limit: int = Query(50, ge=1, le=1000), use_ai: bool = True,
             kev_only: bool = False):
    """Findings ranked by contextual risk score, with plain-English reasons."""
    f = _analysis(use_ai=use_ai).findings
    if kev_only:
        f = f[f["in_kev"]]
    return _records(f.head(limit), FINDING_COLS)


@app.post("/findings/score", tags=["analysis"])
def findings_custom(weights: Weights, limit: int = Query(50, ge=1, le=1000), use_ai: bool = True):
    """Re-rank findings with custom weights (normalised to sum to 1)."""
    if sum(weights.model_dump().values()) == 0:
        raise HTTPException(400, "At least one weight must be > 0")
    f = _analysis(weights.model_dump(), use_ai).findings
    return _records(f.head(limit), FINDING_COLS)


@app.get("/attack-paths", tags=["attack graph"])
def attack_paths(limit: int = Query(20, ge=1, le=500)):
    """Modelled attack paths from the Internet to crown jewels, most likely first."""
    return [{"path": p.nodes, "probability": round(p.probability, 4), "hops": len(p.nodes) - 1,
             "cves": p.cves,
             "attack_techniques": [{"id": t, "name": attack.name(t), "tactic": attack.tactic(t)}
                                   for t in (p.techniques or [])]}
            for p in _analysis().paths[:limit]]


@app.get("/choke-points", tags=["attack graph"])
def choke_points():
    """Assets that many attack paths pass through, and the minimum node cut."""
    return _records(_analysis().choke, ["asset_id", "paths_through", "share_of_paths", "in_min_cut"])


@app.post("/what-if", tags=["remediation"])
def what_if(req: WhatIfRequest):
    """Simulate patching findings and compare risk before and after."""
    a = _analysis()
    known = set(a.findings["finding_id"])
    unknown = [x for x in req.patched_finding_ids if x not in known]
    if unknown:
        raise HTTPException(404, f"Unknown finding id(s): {unknown}")
    before = {k: v for k, v in a.metrics.items() if k != "per_target"}
    after = evaluate_patch_set(a.dataset.assets, a.dataset.edges, a.findings,
                               set(req.patched_finding_ids))
    after.pop("per_target", None)
    removed = (1 - after["crown_jewel_risk"] / before["crown_jewel_risk"]) * 100 \
        if before["crown_jewel_risk"] else 0.0
    return {"before": before, "after": after, "risk_removed_pct": round(removed, 1)}


@app.get("/fix-plan", tags=["remediation"])
def fix_plan(k: int = Query(10, ge=1, le=50)):
    """Greedy graph-aware remediation plan: best fixes in order."""
    a = _analysis()
    return greedy_fix_plan(a.dataset.assets, a.dataset.edges, a.findings, k).to_dict("records")


@app.get("/evaluation", tags=["remediation"])
def evaluation(k: int = Query(5, ge=1, le=20)):
    """Remaining crown-jewel risk after k fixes: CVSS-only vs contextual vs graph-aware."""
    a = _analysis()
    comp = compare_strategies(a.dataset.assets, a.dataset.edges, a.findings, k)
    last = comp[comp["fixes_applied"] == k]
    return {"k": k, "baseline_risk": a.metrics["crown_jewel_risk"],
            "results": last.to_dict("records")}


@app.get("/model", tags=["AI model"])
def model_info():
    """AI exploit-predictor metrics vs a CVSS-only baseline, plus top learned features."""
    m = _model()
    if m is None:
        raise HTTPException(404, "No trained model found")
    return {"metrics": m.metrics, "top_features": m.top_features[:15]}

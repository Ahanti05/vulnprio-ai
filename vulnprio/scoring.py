"""Contextual risk scoring with human-readable explanations.

Score (0-100) = 100 * sum(weight_i * factor_i), where every factor is in [0, 1]:

    severity    = CVSS base score / 10                     (0.5 if unknown)
    exploit     = 1.0 if in CISA KEV, else blend of EPSS percentile and the
                  ML exploit-likelihood percentile (if a model is available)
    criticality = business importance of the asset
    exposure    = internet / internal / isolated
    path        = share of modelled attack paths that use this asset
                  (halved for local-only vulnerabilities)

The weights are initial assumptions (see config.DEFAULT_WEIGHTS) and are
evaluated against a CVSS-only baseline in scripts/evaluate.py.
"""
from __future__ import annotations

import math

import pandas as pd

from .attack import technique_for_finding
from .config import (CRITICALITY, DEFAULT_WEIGHTS, EPSS_BLEND, EXPOSURE, LOCAL_PATH_FACTOR,
                     ML_BLEND, NETWORK_VECTORS)


def _num(x, default=None):
    try:
        x = float(x)
        return default if math.isnan(x) else x
    except (TypeError, ValueError):
        return default


def is_network_exploitable(attack_vector) -> bool:
    """True if the CVE can be triggered remotely. Unknown vectors count as remote
    (conservative assumption, flagged in the explanation)."""
    if attack_vector is None or (isinstance(attack_vector, float) and math.isnan(attack_vector)):
        return True
    return str(attack_vector).upper() in NETWORK_VECTORS


def enables_compromise(conf_impact, integ_impact) -> bool:
    """A CVE counts as an attack step only if it can give an attacker real
    access (High confidentiality or integrity impact). DoS-only or minor
    info leaks do not move an attacker forward. Unknown impact (e.g. CVSS v2
    records) is treated conservatively as enabling."""
    vals = [str(v).upper() for v in (conf_impact, integ_impact)
            if v is not None and not (isinstance(v, float) and math.isnan(v))]
    return True if not vals else "HIGH" in vals


def exploit_likelihood(in_kev: bool, epss_pct, ml_pct=None) -> float:
    """Exploit-likelihood factor E in [0, 1]."""
    if in_kev:
        return 1.0
    epss_pct = _num(epss_pct)
    ml_pct = _num(ml_pct)
    if epss_pct is not None and ml_pct is not None:
        return EPSS_BLEND * epss_pct + ML_BLEND * ml_pct
    if epss_pct is not None:
        return epss_pct
    if ml_pct is not None:
        return ml_pct
    return 0.3  # unknown: neutral-low assumption


def add_exploit_factor(findings: pd.DataFrame) -> pd.DataFrame:
    f = findings.copy()
    if "ml_percentile" not in f:
        f["ml_percentile"] = None
    for col in ("conf_impact", "integ_impact"):
        if col not in f:
            f[col] = None
    f["remote"] = f["attack_vector"].map(is_network_exploitable)
    f["high_impact"] = [enables_compromise(c, i) for c, i in zip(f["conf_impact"], f["integ_impact"])]
    # network_exploitable = can be used as a step in an attack path
    f["network_exploitable"] = f["remote"] & f["high_impact"]
    if "user_interaction" not in f:
        f["user_interaction"] = None
    f["attack_technique"] = [technique_for_finding(r, e, u) for r, e, u in
                             zip(f["remote"],
                                 f["exposure"] if "exposure" in f else ["internal"] * len(f),
                                 f["user_interaction"])]
    f["f_exploit"] = [exploit_likelihood(k, e, m) for k, e, m in
                      zip(f["in_kev"], f["epss_percentile"], f["ml_percentile"])]
    return f


def score_findings(findings: pd.DataFrame, path_share: dict[str, float],
                   weights: dict[str, float] | None = None) -> pd.DataFrame:
    """Return findings with factor columns, contextual score, ranks and explanations."""
    w = dict(DEFAULT_WEIGHTS)
    w.update(weights or {})
    total = sum(w.values()) or 1.0
    w = {k: v / total for k, v in w.items()}   # normalise so weights sum to 1

    f = findings.copy()
    if "f_exploit" not in f:
        f = add_exploit_factor(f)
    f["f_severity"] = f["cvss_score"].map(lambda s: _num(s, 5.0) / 10.0)
    f["f_criticality"] = f["criticality"].map(CRITICALITY).fillna(0.5)
    f["f_exposure"] = f["exposure"].map(EXPOSURE).fillna(0.6)
    f["f_path"] = [path_share.get(a, 0.0) * (1.0 if net else LOCAL_PATH_FACTOR)
                   for a, net in zip(f["asset_id"], f["network_exploitable"])]

    f["contextual_score"] = 100 * (
        w["severity"] * f["f_severity"] + w["exploit"] * f["f_exploit"]
        + w["criticality"] * f["f_criticality"] + w["exposure"] * f["f_exposure"]
        + w["path"] * f["f_path"])
    f["contextual_score"] = f["contextual_score"].round(1)

    # CVSS-only baseline (ties broken by finding id for determinism)
    f["cvss_rank"] = f["cvss_score"].fillna(0).rank(ascending=False, method="first").astype(int)
    f = f.sort_values(["contextual_score", "cvss_score"], ascending=False).reset_index(drop=True)
    f["contextual_rank"] = range(1, len(f) + 1)
    f["rank_shift"] = f["cvss_rank"] - f["contextual_rank"]   # +ve = moved up vs CVSS-only
    f["explanation"] = [explain(r, w) for r in f.to_dict("records")]
    return f


def explain(r: dict, w: dict) -> str:
    """Build a short rationale listing the strongest contributing factors."""
    reasons = []
    contrib = {k: w[k] * r[f"f_{k}"] for k in w}
    order = sorted(contrib, key=contrib.get, reverse=True)
    for k in order[:3]:
        if k == "exploit":
            if r.get("in_kev"):
                reasons.append("listed in CISA KEV (known to be exploited)")
            elif _num(r.get("epss")) is not None:
                reasons.append(f"EPSS {float(r['epss']):.3f} (higher than "
                               f"{float(r['epss_percentile']) * 100:.0f}% of CVEs)")
            else:
                reasons.append("exploit likelihood unknown")
        elif k == "severity":
            s = _num(r.get("cvss_score"))
            reasons.append(f"CVSS {s:.1f}" if s is not None else "CVSS unknown")
        elif k == "criticality":
            reasons.append(f"{r.get('criticality')}-criticality asset"
                           + (" (crown jewel)" if r.get("crown_jewel") else ""))
        elif k == "exposure":
            reasons.append({"internet": "internet-facing", "internal": "internal network",
                            "isolated": "isolated network"}.get(r.get("exposure"), "exposure unknown"))
        elif k == "path":
            share = r.get("f_path", 0)
            reasons.append(f"on {share * 100:.0f}% of attack paths to critical assets"
                           if share > 0 else "not on any modelled attack path")
    if not r.get("remote", True):
        reasons.append("local-only attack vector")
    elif not r.get("high_impact", True):
        reasons.append("limited impact (no high confidentiality/integrity impact)")
    return "; ".join(reasons).capitalize()

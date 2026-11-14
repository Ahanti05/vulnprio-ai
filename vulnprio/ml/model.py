"""Exploit-likelihood model (the AI component).

Task:   predict whether a CVE ends up in the CISA KEV catalog
        (i.e. is known to be exploited in the wild).
Input:  CVE description text (TF-IDF, NLP) + CVSS metrics + CWE + vendor.
Model:  class-balanced Logistic Regression (fast, interpretable coefficients).
Split:  time-based - train on older CVEs, test on newer ones, so the model is
        evaluated on CVEs it could not have "seen", like in real use.

The output is used as one input to the exploit factor E when a CVE is not
already in KEV. It does not replace EPSS; it complements it and also works
for brand-new CVEs that EPSS has not scored yet.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from ..config import MODEL_PATH

CATEGORICAL = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction",
               "scope", "conf_impact", "integ_impact", "avail_impact", "cwe", "vendor"]
NUMERIC = ["cvss_score"]
TEXT = "description"


def prepare(df: pd.DataFrame) -> pd.DataFrame:
    x = pd.DataFrame(index=df.index)
    for c in CATEGORICAL:
        x[c] = df[c].fillna("unknown").astype(str) if c in df else "unknown"
    x["cvss_score"] = pd.to_numeric(df.get("cvss_score"), errors="coerce").fillna(5.0)
    x[TEXT] = df[TEXT].fillna("").astype(str) if TEXT in df else ""
    return x


def build_pipeline() -> Pipeline:
    features = ColumnTransformer([
        ("text", TfidfVectorizer(max_features=8000, ngram_range=(1, 2), min_df=3,
                                 sublinear_tf=True, stop_words="english"), TEXT),
        ("cat", OneHotEncoder(handle_unknown="ignore", min_frequency=15), CATEGORICAL),
        ("num", StandardScaler(), NUMERIC),
    ])
    clf = LogisticRegression(class_weight="balanced", max_iter=3000, C=0.5)
    return Pipeline([("features", features), ("clf", clf)])


def precision_at_k(y_true, scores, k: int) -> float:
    idx = np.argsort(-np.asarray(scores))[:k]
    return float(np.asarray(y_true)[idx].mean())


class ExploitModel:
    def __init__(self, pipeline: Pipeline, reference: np.ndarray, metrics: dict,
                 top_features: list):
        self.pipeline = pipeline
        self.reference = np.sort(reference)
        self.metrics = metrics
        self.top_features = top_features

    # ------------------------------------------------------------------ train
    @classmethod
    def train(cls, data: pd.DataFrame, split_date: str = "2023-01-01") -> "ExploitModel":
        data = data.dropna(subset=["published"]).copy()
        train = data[data["published"] < split_date]
        test = data[data["published"] >= split_date]
        pipe = build_pipeline()
        pipe.fit(prepare(train), train["label_kev"])

        p_test = pipe.predict_proba(prepare(test))[:, 1]
        y = test["label_kev"].to_numpy()
        cvss = pd.to_numeric(test["cvss_score"], errors="coerce").fillna(0).to_numpy()
        k = 100
        metrics = {
            "train_size": int(len(train)), "train_positives": int(train["label_kev"].sum()),
            "test_size": int(len(test)), "test_positives": int(y.sum()),
            "split": f"train: published before {split_date}; test: on/after {split_date}",
            "model": {"roc_auc": round(roc_auc_score(y, p_test), 4),
                      "pr_auc": round(average_precision_score(y, p_test), 4),
                      f"precision_at_{k}": round(precision_at_k(y, p_test, k), 4)},
            "cvss_only_baseline": {"roc_auc": round(roc_auc_score(y, cvss), 4),
                                   "pr_auc": round(average_precision_score(y, cvss), 4),
                                   f"precision_at_{k}": round(precision_at_k(y, cvss, k), 4)},
            "random_baseline_pr_auc": round(float(y.mean()), 4),
        }
        names = pipe.named_steps["features"].get_feature_names_out()
        coefs = pipe.named_steps["clf"].coef_[0]
        order = np.argsort(-coefs)[:25]
        top = [{"feature": str(names[i]).replace("text__", "word: ").replace("cat__", ""),
                "weight": round(float(coefs[i]), 3)} for i in order]
        return cls(pipe, p_test, metrics, top)

    # ---------------------------------------------------------------- predict
    def predict(self, df: pd.DataFrame):
        """Return (probability, percentile vs. test-set CVEs) arrays."""
        if df.empty:
            return np.array([]), np.array([])
        p = self.pipeline.predict_proba(prepare(df))[:, 1]
        pct = np.searchsorted(self.reference, p, side="right") / len(self.reference)
        return p, pct

    # ------------------------------------------------------------- persistence
    def save(self, path: Path = MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": self.pipeline, "reference": self.reference,
                     "metrics": self.metrics, "top_features": self.top_features}, path,
                    compress=3)

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "ExploitModel | None":
        if not Path(path).exists():
            return None
        b = joblib.load(path)
        return cls(b["pipeline"], b["reference"], b["metrics"], b["top_features"])

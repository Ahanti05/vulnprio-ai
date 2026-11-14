"""Central configuration: paths, factor mappings and default weights.

All weights here are *initial, documented assumptions*. They are meant to be
tuned and validated experimentally (see docs/METHODOLOGY.md), not treated as
final truths.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
SAMPLE_DIR = DATA_DIR / "sample"
CACHE_DIR = DATA_DIR / "cache"
ML_DATA_DIR = DATA_DIR / "ml"
MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "exploit_model.joblib"

# Asset business criticality -> numeric value in [0, 1]
CRITICALITY = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}

# Network exposure of an asset -> numeric value in [0, 1]
EXPOSURE = {"internet": 1.0, "internal": 0.6, "isolated": 0.3}

# Default weights of the contextual risk score (must sum to 1.0)
DEFAULT_WEIGHTS = {
    "severity": 0.30,     # CVSS base score / 10
    "exploit": 0.25,      # KEV / EPSS / ML exploit likelihood
    "criticality": 0.15,  # business importance of the asset
    "exposure": 0.15,     # internet-facing vs internal vs isolated
    "path": 0.15,         # share of attack paths that use this asset
}

# How the exploit-likelihood signal E is blended when the CVE is NOT in KEV
EPSS_BLEND = 0.6          # weight of EPSS percentile
ML_BLEND = 0.4            # weight of ML percentile (used only if a model exists)

# Attack-vector values (CVSS v2/v3/v4) that allow a remote/adjacent attacker
NETWORK_VECTORS = {"NETWORK", "ADJACENT_NETWORK", "ADJACENT"}

# Attack graph settings
ENTRY_NODE = "INTERNET"
PATH_CUTOFF = 8           # max hops for path enumeration
MAX_PATHS = 20000         # safety cap for path enumeration
MIN_STEP_PROB = 0.05      # floor for a single attack-step likelihood
MAX_STEP_PROB = 0.95      # ceiling for a single attack-step likelihood
LOCAL_PATH_FACTOR = 0.5   # path relevance multiplier for local-only vulns

USER_AGENT = "vulnprio-ai/0.1 (academic B.Tech project; defensive research)"

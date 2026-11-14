# Methodology

## 1. Data
| Source | What we use | How |
|---|---|---|
| NVD CVE API 2.0 | CVSS (v3.1 preferred, then v3.0, v4.0, v2), attack vector, CWE, vendor, description | `vulnprio/ingest/nvd.py` |
| FIRST EPSS | probability and percentile of exploitation in next 30 days | `vulnprio/ingest/epss.py` |
| CISA KEV | known-exploited flag, date added, ransomware use | `vulnprio/ingest/kev.py` |
| Organisation (synthetic) | assets, criticality, exposure, network flows, scan findings | `data/sample/*.csv` |

All CVE data is saved as a dated snapshot (`data/sample/cve_intel.csv`) so results are reproducible.

## 2. Contextual risk score
Each finding gets five factors in [0, 1]:

| Factor | Definition | Default weight |
|---|---|---|
| Severity | CVSS base score / 10 (0.5 if unknown) | 0.30 |
| Exploit | 1.0 if in KEV, else 0.6 × EPSS percentile + 0.4 × AI-model percentile | 0.25 |
| Criticality | low 0.25 · medium 0.5 · high 0.75 · critical 1.0 | 0.15 |
| Exposure | internet 1.0 · internal 0.6 · isolated 0.3 | 0.15 |
| Path | share of modelled attack paths through the asset (× 0.5 for local-only CVEs) | 0.15 |

`Score = 100 × Σ weight × factor`. Weights are **initial assumptions** to be checked with a
sensitivity study; the dashboard lets you change them live.

## 3. Attack graph
- Nodes: `INTERNET` + every asset. Crown jewels = assets marked critical.
- **Edge rule:** `u → v` exists if the network allows `u` to reach `v` **and** `v` has an unpatched,
  network-exploitable vulnerability.
- Step likelihood `p(v)` = highest exploit factor among those vulnerabilities, clipped to [0.05, 0.95].
- Edge weight = `−log p`, so Dijkstra's shortest path = most likely attack path.
- Path probability = product of step likelihoods (assumes independent steps).
- Choke points: (a) how many paths pass through each asset, (b) minimum node cut between
  `INTERNET` and all crown jewels.

## 4. Remediation
- **What-if:** remove patched findings, rebuild graph, compare metrics.
- **Greedy plan:** at each step pick the fix that removes the most crown-jewel risk
  (sum of most-likely-path probabilities); ties broken by contextual score.

## 5. AI model
- Label: CVE is in CISA KEV (1) or not (0).
- Features: TF-IDF of description (1–2 grams), one-hot CVSS metrics, CWE, vendor; CVSS score.
- Model: class-balanced Logistic Regression (interpretable coefficients).
- Split by **time** (train on older CVEs, test on newer) to avoid look-ahead.
- Metrics: ROC-AUC, PR-AUC, Precision@100, compared with a CVSS-only baseline.

## 6. Assumptions and limitations
- The demo network is synthetic; real organisational data may differ.
- An attack edge is a modelled possibility, not a confirmed exploit.
- Local-only CVEs do not create network edges (privilege escalation is out of scope for v1).
- KEV is incomplete: "not in KEV" does not mean "never exploited", so the AI labels contain noise.
- NVD/KEV records are current snapshots, so some information may post-date a CVE's
  publication (mild leakage), partly reduced by the time-based split.

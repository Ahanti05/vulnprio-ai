# 🛡️ VulnPrio AI

![python](https://img.shields.io/badge/python-3.9%2B-blue) ![license](https://img.shields.io/badge/use-defensive%20only-red)

### AI-Based Vulnerability Prioritization & Attack-Path Analysis
*A context-aware approach to cybersecurity risk assessment and remediation*

> **"What should we fix first, and why?"**

Most teams patch by CVSS score. But a CVSS 9.8 bug on an isolated test box can matter far less than a
CVSS 7.5 bug on an internet-facing server one hop away from the customer database.
**VulnPrio AI** ranks vulnerabilities by *real-world context*: exploitation evidence, an AI exploit
predictor, asset importance, network exposure, and position on attack paths to critical systems.

B.Tech CSE final-year major project · PVPIT Budhgaon, Sangli · DBATU · 2026–27

---

## ✨ Features
- **Real threat intelligence:** NVD CVE API 2.0, FIRST EPSS, CISA KEV (cached, dated snapshots)
- **🤖 AI exploit predictor:** NLP model (TF-IDF + Logistic Regression) trained on 54k real CVEs to
  predict which ones get exploited
- **Contextual risk score (0–100)** from 5 transparent factors, with a plain-English reason for every finding
- **Attack graph:** NetworkX model of how an attacker could move from the Internet to crown-jewel assets
- **Most-likely attack paths**, **choke points** (minimum node cut) and **what-if fix simulation**
- **Graph-aware "Fix First" plan:** a greedy optimiser that picks the fixes that cut the most risk
- **MITRE ATT&CK mapping:** every attack step is labelled with the matching technique (T1190, T1210, T1203, T1068)
- **REST API backend (FastAPI):** findings, attack paths, what-if, fix plan and model metrics as JSON, with Swagger docs at `/docs`
- **Built-in evaluation** against a CVSS-only baseline
- **Beginner-friendly dashboard** (Streamlit, dark security theme): 8 plain-English tabs, a 4-step explainer, a glossary, an interactive attack map, what-if fixes, and CSV upload/export
- 14 automated tests (engine + API) · Docker image · one-click Render deployment

## 📈 Results so far
**AI model:** trained on CVEs from 2019–2020 and tested on 18,544 *unseen* CVEs from 2021 (202 later known exploited):

| Metric | AI model | CVSS-only |
|---|---|---|
| ROC-AUC | **0.841** | 0.719 |
| PR-AUC | **0.084** | 0.023 |
| Precision@100 | **18%** | 4% |

**Remediation (synthetic network):** fixing the top 5 findings removes **0%** of modelled crown-jewel risk with CVSS-only ranking vs **100%** with our contextual ranking. See [docs/RESULTS.md](docs/RESULTS.md).

**Scalability:** a full analysis of 2,000 assets and 3,935 findings runs in **under 1 second** on a laptop. **Weight sensitivity:** the ranking stays stable across 300 random weight settings (mean Kendall's τ 0.70). See [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md).
*Network results are simulation-based; see limitations in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).*

## 🏗️ Architecture
```mermaid
flowchart LR
  A[NVD CVE API] --> I[Ingestion + cache]
  B[FIRST EPSS] --> I
  C[CISA KEV] --> I
  D[Assets, network flows,<br/>scan findings] --> P[Preprocessing<br/>dedup + validation]
  I --> P
  P --> M[AI exploit model<br/>NLP + LogReg]
  M --> E[Exploit factor]
  P --> E
  E --> G[Attack graph<br/>NetworkX]
  G --> X[Paths, choke points,<br/>path share]
  X --> S[Contextual risk score<br/>+ explanations]
  E --> S
  S --> R[Fix-First plan<br/>what-if simulation]
  G --> R
  S --> UI[Streamlit dashboard]
  S --> API[FastAPI REST API]
  R --> API
  R --> UI
  X --> UI
```

## 🚀 Quick start
```bash
git clone https://github.com/Ahanti05/vulnprio-ai.git
cd vulnprio-ai
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```
The sample data and trained model are included, so the dashboard works offline straight away.

### Backend API
```bash
uvicorn api:app --reload        # then open http://localhost:8000/docs
```
| Endpoint | What it returns |
|---|---|
| `GET /summary` | headline numbers: attack paths, exposed crown jewels, risk |
| `GET /findings` | ranked findings with reasons (`?kev_only=true`, `?limit=`) |
| `POST /findings/score` | re-rank with custom weights |
| `GET /attack-paths` | most likely paths with CVEs and MITRE ATT&CK techniques |
| `GET /choke-points` | choke points and minimum cut |
| `POST /what-if` | before/after risk for a set of fixes |
| `GET /fix-plan` | greedy graph-aware remediation plan |
| `GET /evaluation` | CVSS-only vs contextual vs graph-aware after *k* fixes |
| `GET /model` | AI model metrics and top features |

### Deploy (free) on Render
`render.yaml` deploys **both** services: Render → *New* → *Blueprint* → select this repo → *Apply*.

### Docker
```bash
docker build -t vulnprio-ai .
docker run -p 8501:8501 vulnprio-ai                                  # dashboard
docker run -p 8000:8000 vulnprio-ai uvicorn api:app --host 0.0.0.0    # API
```

### Rebuild everything from live data (optional)
```bash
python scripts/build_ml_dataset.py --start 2019-01-01 --end 2021-12-07   # ~10 min, NVD rate limit
python scripts/train_model.py --split 2021-01-01
python scripts/fetch_intel.py --refresh        # live CVSS / EPSS / KEV for the sample findings
python scripts/evaluate.py                     # writes docs/RESULTS.md
python scripts/experiments.py                  # writes docs/EXPERIMENTS.md
pytest -q
```
Tip: set `NVD_API_KEY` (free from NVD) to download about 10× faster.

## 📁 Project structure
```
vulnprio/
  ingest/      nvd.py, epss.py, kev.py, enrich.py   - threat-intel collection
  loader.py    data loading, cleaning, validation
  scoring.py   contextual risk score + explanations
  graph.py     attack graph, paths, choke points, risk metrics
  remediation.py  what-if, greedy fix plan, strategy comparison
  ml/model.py  AI exploit-likelihood model
  attack.py    MITRE ATT&CK technique mapping
  analysis.py  end-to-end pipeline
app.py         Streamlit dashboard (frontend)
api.py         FastAPI REST API (backend)
scripts/       data download, training, evaluation
data/sample/   synthetic company network + CVE snapshot
models/        trained model + metrics
tests/         pytest unit tests
docs/          methodology and results
```

## 📚 Documentation
| Doc | What's inside |
|---|---|
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Data sources, risk formula, attack-graph rules, AI model, limitations |
| [docs/DIAGRAMS.md](docs/DIAGRAMS.md) | DFD level 0/1, use case, class, sequence, activity, ER and deployment diagrams |
| [docs/RESULTS.md](docs/RESULTS.md) | CVSS-only vs contextual vs graph-aware remediation experiment |
| [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) | Weight sensitivity and scalability benchmarks |
| [docs/VIVA.md](docs/VIVA.md) | 2-minute demo script and 16 likely viva questions with answers |

## 🔒 Ethics and scope
Defensive decision-support only. It never scans or exploits anything. The demo network is
**synthetic**, and real scanning should only be done on systems you own or are authorised to test.
A modelled attack path is a planning aid, not proof that an attack is possible.

## 🗺️ Roadmap
See [ROADMAP.md](ROADMAP.md): Semester 7 (80%, core system) and Semester 8 (20%, SHAP, scalability, ATT&CK, API, deployment, paper).

## 📚 Key references
- NIST NVD Vulnerability APIs: https://nvd.nist.gov/developers/vulnerabilities
- FIRST EPSS: https://www.first.org/epss/ · FIRST CVSS v4.0: https://www.first.org/cvss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NetworkX: https://networkx.org · scikit-learn: https://scikit-learn.org

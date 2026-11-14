# Roadmap — two semesters (80% / 20%)

Legend: ✅ done in this repo · 🔄 in progress · ⬜ planned

## Semester 7 — build 80% (working system + first results)

| # | Work package | Status | Owner |
|---|---|---|---|
| 1 | Project setup, repo, environment, coding standards | ✅ | Member A |
| 2 | NVD / EPSS / CISA KEV data ingestion with caching and snapshots | ✅ | Member B |
| 3 | Synthetic company network (19 assets, 39 network flows, 31 findings, real CVEs) | ✅ | Member A |
| 4 | Data preprocessing: dedup, validation, missing-data report | ✅ | Member B |
| 5 | Contextual risk score (5 factors) + plain-English explanations | ✅ | Member C |
| 6 | CVSS-only baseline ranking | ✅ | Member C |
| 7 | Attack graph (NetworkX), path enumeration, most-likely path | ✅ | Member D |
| 8 | Choke points (path share + minimum node cut) | ✅ | Member D |
| 9 | What-if fix simulation (before/after) | ✅ | Member D |
| 10 | Greedy graph-aware "Fix First" plan | ✅ | Member C |
| 11 | AI model: NLP exploit-likelihood (TF-IDF + Logistic Regression, KEV labels, time split) | ✅ | Member B |
| 12 | Beginner-friendly Streamlit dashboard (8 tabs, 4-step explainer, glossary, interactive attack map, CSV upload/export) | ✅ | Member A |
| 13 | Unit tests (pytest) | ✅ | All |
| 14 | First experiment: CVSS-only vs contextual vs graph-aware (docs/RESULTS.md) | ✅ | Member C |
| 15 | Team understands and can demo every module | ⬜ | All |
| 16 | Synthetic network generator (50–2,000 assets) for testing at scale | ✅ | Member A |
| 17 | Weight sensitivity study (how rankings change with weights) | ✅ | Member C |
| 18 | UML/DFD/ER/deployment diagrams (docs/DIAGRAMS.md) | ✅ | Member A + B |
| 18b | Report chapters 1–5 | ⬜ | Member A + B |
| 19 | Viva guide and demo script (docs/VIVA.md) | ✅ | All |
| 20 | Sem-7 presentation and demo | ⬜ | All |

## Semester 8 — final 20% (depth, polish, publication)

| # | Work package | Owner |
|---|---|---|
| 0 | Extend AI training data to 2019–2024 CVEs | Member B |
| 1 | Stronger AI: XGBoost/LightGBM + SHAP explanations, compare with Logistic Regression | Member B |
| 2 | Scalability study at larger scale (10k+ assets, denser graphs, charts); first benchmark done | Member D |
| 3 | Real scanner input: OpenVAS/Nmap on the team's **own** lab VMs (authorised only) | Member A |
| 4 | Map attack steps to MITRE ATT&CK techniques | Member D |
| 5 | FastAPI backend + login (Admin / Analyst) | Member C |
| 6 | Docker image + free public demo (Streamlit Community Cloud) | Member A |
| 7 | GitHub Actions CI running tests on every push | Member C |
| 8 | Final report, viva prep, research paper submission (conference / journal) | All |

## Future scope (not planned for this project)
Zero-day detection, cloud/IoT asset models, live continuous monitoring, automated ticketing
(Jira/ServiceNow) after analyst approval.

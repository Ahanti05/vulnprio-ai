# Experiment results (synthetic network, real CVE data)

Snapshot: 2026-11-15 · AI model used: True

- Findings: 31 on 19 assets
- Attack paths to crown jewels: 3
- Crown jewels reachable: 2/4
- Baseline crown-jewel risk: 1.6719

## Risk remaining after fixing the top 5 findings

| Strategy | Crown-jewel risk | Risk removed | Attack paths left | Crown jewels reachable |
|---|---|---|---|---|
| CVSS-only | 1.6719 | 0.0% | 3 | 2 |
| Contextual score | 0.0 | 100.0% | 0 | 0 |
| Graph-aware plan | 0.0 | 100.0% | 0 | 0 |

## Top 5 by each ranking

| # | CVSS-only | Contextual |
|---|---|---|
| 1 | CVE-2019-11510 on vpn-01 (CVSS 10.0) | CVE-2021-26855 on mail-01 (score 88.6) |
| 2 | CVE-2021-44228 on app-01 (CVSS 10.0) | CVE-2019-11510 on vpn-01 (score 86.3) |
| 3 | CVE-2021-41773 on web-01 (CVSS 9.8) | CVE-2019-0708 on admin-ws (score 84.6) |
| 4 | CVE-2021-42013 on web-01 (CVSS 9.8) | CVE-2022-21907 on hr-db (score 83.2) |
| 5 | CVE-2023-34362 on mft-01 (CVSS 9.8) | CVE-2023-23397 on ws-01 (score 80.9) |

## Greedy graph-aware plan

|   step | finding_id   | asset_id   | cve_id         | component                 |   contextual_score |   attack_paths_after |   crown_jewel_risk_after |   risk_removed_pct |
|-------:|:-------------|:-----------|:---------------|:--------------------------|-------------------:|---------------------:|-------------------------:|-------------------:|
|      1 | F007         | mail-01    | CVE-2021-26855 | Microsoft Exchange        |               88.6 |                    1 |                   0.8145 |               51.3 |
|      2 | F030         | admin-ws   | CVE-2019-0708  | Remote Desktop (BlueKeep) |               84.6 |                    0 |                   0      |              100   |
|      3 | F005         | vpn-01     | CVE-2019-11510 | Pulse Connect Secure      |               86.3 |                    0 |                   0      |              100   |
|      4 | F020         | hr-db      | CVE-2022-21907 | Windows HTTP.sys          |               83.2 |                    0 |                   0      |              100   |
|      5 | F026         | ws-01      | CVE-2023-23397 | Microsoft Outlook         |               80.9 |                    0 |                   0      |              100   |
|      6 | F001         | web-01     | CVE-2021-41773 | Apache httpd 2.4.49       |               80.6 |                    0 |                   0      |              100   |
|      7 | F002         | web-01     | CVE-2021-42013 | Apache httpd 2.4.49       |               80.6 |                    0 |                   0      |              100   |
|      8 | F021         | backup-01  | CVE-2014-0160  | OpenSSL (Heartbleed)      |               77   |                    0 |                   0      |              100   |
|      9 | F008         | mft-01     | CVE-2023-34362 | MOVEit Transfer           |               76.9 |                    0 |                   0      |              100   |
|     10 | F009         | app-01     | CVE-2021-44228 | Apache Log4j 2            |               75.2 |                    0 |                   0      |              100   |

## Notes and limitations

- The network is synthetic; results show how the method behaves, not real-world performance.
- Attack edges follow the modelling rule in vulnprio/graph.py; an edge is not proof of exploitability.
- 'Crown-jewel risk' = sum over critical assets of the most likely path probability.
- Weights are initial assumptions; a sensitivity study is planned (see ROADMAP.md).

## AI exploit-likelihood model

train: published before 2021-01-01; test: on/after 2021-01-01. Train 35,627 CVEs, test 18,544 CVEs (202 known exploited).

| Metric | AI model | CVSS-only |
|---|---|---|
| roc_auc | 0.8411 | 0.719 |
| pr_auc | 0.0838 | 0.0233 |
| precision_at_100 | 0.18 | 0.04 |

Random-guess PR-AUC: 0.0109

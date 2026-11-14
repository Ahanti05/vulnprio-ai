# Additional experiments

## 1. Weight sensitivity (sample network)

300 random weight settings (Dirichlet, α=2) compared with the default weights.

| Measure | Mean | Min | Max |
|---|---|---|---|
| Kendall's τ vs default ranking | 0.699 | 0.325 | 0.940 |
| Top-5 overlap with default | 69% | 20% | 100% |

Same #1 finding in 75% of runs. For comparison, Kendall's τ between the default ranking and the CVSS-only ranking is **0.471**.

**Removing one factor at a time** (weight set to 0):

| Factor removed | Kendall's τ vs default | Top-5 kept |
|---|---|---|
| severity | 0.690 | 4/5 |
| exploit | 0.884 | 5/5 |
| criticality | 0.763 | 4/5 |
| exposure | 0.811 | 4/5 |
| path | 0.763 | 3/5 |

Reading: a high τ means the ranking is robust to the exact weights; the factor whose removal lowers τ most has the most influence on the ranking.

## 2. Scalability (synthetic layered networks)

2 findings per asset, CVEs sampled from the real snapshot, path cutoff 8 hops, path enumeration capped at 20,000 paths. Single run, Apple-silicon laptop, no AI model.

| Assets | Network edges | Findings | Attack paths found | Analysis time (s) | Peak memory (MB) |
|---|---|---|---|---|---|
| 49 | 104 | 96 | 9 | 0.03 | 1 |
| 100 | 212 | 194 | 11 | 0.04 | 1 |
| 249 | 525 | 488 | 13 | 0.09 | 3 |
| 500 | 1053 | 984 | 36 | 0.21 | 6 |
| 1000 | 2101 | 1969 | 47 | 0.37 | 12 |
| 2000 | 4203 | 3935 | 115 | 0.93 | 23 |

Note: path enumeration is exponential in the worst case; the cap keeps run time bounded. Most-likely-path risk uses Dijkstra (O(E log V)) and is not capped.


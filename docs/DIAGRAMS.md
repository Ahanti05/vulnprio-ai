# System design diagrams

These diagrams render on GitHub. For the report, open each one in https://mermaid.live,
choose a plain black-and-white theme, and export as PNG/SVG.

---

## 1. DFD level 0 (context diagram)
```mermaid
flowchart LR
  ANALYST([Security analyst])
  NVD([NVD CVE API])
  EPSS([FIRST EPSS API])
  KEV([CISA KEV feed])
  ORG([Organisation data<br/>assets, network flows, scan findings])
  SYS((VulnPrio AI<br/>system))
  NVD -- CVE records --> SYS
  EPSS -- exploit probabilities --> SYS
  KEV -- known-exploited list --> SYS
  ORG -- CSV files --> SYS
  ANALYST -- weights, what-if fixes --> SYS
  SYS -- ranked findings, attack paths,<br/>Fix-First plan, explanations --> ANALYST
```

## 2. DFD level 1
```mermaid
flowchart TB
  IN1[/NVD, EPSS, KEV/] --> P1(1.0 Collect threat intel)
  IN2[/assets, edges, findings CSV/] --> P2(2.0 Preprocess and validate)
  P1 --> D1[(D1 CVE intel snapshot)]
  D1 --> P2
  P2 --> D2[(D2 Clean findings)]
  D3[(D3 Trained AI model)] --> P3(3.0 Compute exploit likelihood)
  D2 --> P3
  P3 --> P4(4.0 Build attack graph)
  P4 --> P5(5.0 Find paths and choke points)
  P5 --> P6(6.0 Contextual risk scoring)
  P3 --> P6
  P6 --> P7(7.0 Remediation planning and what-if)
  P4 --> P7
  P6 --> OUT[/Dashboard and reports/]
  P5 --> OUT
  P7 --> OUT
```

## 3. Use case diagram
```mermaid
flowchart LR
  A((Security<br/>analyst))
  AD((Admin))
  subgraph VulnPrio AI
    U1([Upload assets, network and findings])
    U2([Refresh threat intelligence])
    U3([View ranked findings with reasons])
    U4([View attack graph and paths])
    U5([Simulate a fix - what-if])
    U6([Generate Fix-First plan])
    U7([Adjust risk weights])
    U8([Export report CSV])
    U9([Retrain AI model])
  end
  A --- U1
  A --- U3
  A --- U4
  A --- U5
  A --- U6
  A --- U7
  A --- U8
  AD --- U2
  AD --- U9
```

## 4. Class diagram
```mermaid
classDiagram
  class Dataset {
    +DataFrame assets
    +DataFrame edges
    +DataFrame findings
    +list issues
  }
  class ExploitModel {
    +Pipeline pipeline
    +ndarray reference
    +dict metrics
    +train(data, split_date)
    +predict(findings)
    +save() / load()
  }
  class Analysis {
    +DataFrame findings
    +DiGraph graph
    +list paths
    +DataFrame choke
    +dict metrics
  }
  class PathResult {
    +list nodes
    +float probability
    +list cves
  }
  class Loader {
    +load_dataset(dir) Dataset
    +prepare_dataset() Dataset
  }
  class Scoring {
    +exploit_likelihood()
    +score_findings() DataFrame
    +explain() str
  }
  class AttackGraph {
    +build_attack_graph() DiGraph
    +enumerate_paths() list
    +choke_points() DataFrame
    +minimum_cut() set
    +risk_metrics() dict
  }
  class Remediation {
    +evaluate_patch_set() dict
    +greedy_fix_plan() DataFrame
    +compare_strategies() DataFrame
  }
  Loader --> Dataset : creates
  Analysis o-- Dataset
  Analysis o-- PathResult
  Analysis ..> Scoring
  Analysis ..> AttackGraph
  Analysis ..> ExploitModel
  Remediation ..> AttackGraph
```

## 5. Sequence diagram: analyst opens the dashboard
```mermaid
sequenceDiagram
  actor Analyst
  participant UI as Dashboard
  participant L as Loader
  participant M as AI model
  participant S as Scoring
  participant G as Attack graph
  participant R as Remediation
  Analyst->>UI: open app / change weights
  UI->>L: load_dataset()
  L-->>UI: clean assets, edges, findings
  UI->>M: predict(findings)
  M-->>UI: exploit probability + percentile
  UI->>G: build graph, enumerate paths
  G-->>UI: paths, choke points, path share
  UI->>S: score_findings(path share, weights)
  S-->>UI: ranked findings + explanations
  Analyst->>UI: patch finding F007 (what-if)
  UI->>R: evaluate_patch_set({F007})
  R->>G: rebuild graph without F007
  G-->>R: new metrics
  R-->>UI: before vs after
  UI-->>Analyst: risk reduced, paths removed
```

## 6. Activity diagram: risk assessment (matches synopsis §5.8)
```mermaid
flowchart TB
  S([Start]) --> A[Vulnerability finding]
  A --> B[Retrieve CVE metadata: CVSS, EPSS, KEV]
  B --> C[Associate finding with asset]
  C --> D[Gather asset and network context]
  D --> E[Calculate contextual risk]
  E --> F[Analyse asset position in attack graph]
  F --> Q{High priority or<br/>important path?}
  Q -- Yes --> Y1[Flag for early remediation]
  Y1 --> Y2[Assess candidate fix]
  Y2 --> Y3[Re-evaluate affected paths]
  Q -- No --> N1[Retain in ranked findings]
  Y3 --> G[Generate ranked results]
  N1 --> G
  G --> H[Display score, rationale and recommendations]
  H --> E2([End])
```

## 7. ER diagram (data model)
```mermaid
erDiagram
  ASSET ||--o{ FINDING : has
  CVE ||--o{ FINDING : "identified as"
  ASSET ||--o{ NETWORK_EDGE : "source of"
  ASSET ||--o{ NETWORK_EDGE : "target of"
  FINDING ||--o| SCORE : receives
  ASSET {
    string asset_id PK
    string hostname
    string role
    string os
    string zone
    string criticality
    string exposure
    bool crown_jewel
  }
  NETWORK_EDGE {
    string source FK
    string target FK
    int port
    string protocol
  }
  CVE {
    string cve_id PK
    float cvss_score
    string attack_vector
    string cwe
    float epss
    bool in_kev
    date snapshot_date
  }
  FINDING {
    string finding_id PK
    string asset_id FK
    string cve_id FK
    string component
    string scanner
  }
  SCORE {
    string finding_id FK
    float contextual_score
    int contextual_rank
    int cvss_rank
    string explanation
  }
```

## 8. Deployment diagram
```mermaid
flowchart LR
  subgraph User laptop / browser
    B[Web browser]
  end
  subgraph Server or laptop - Python 3.9+
    ST[Streamlit app<br/>app.py]
    CORE[vulnprio package<br/>scoring, graph, AI]
    FS[(CSV snapshots<br/>+ model.joblib)]
  end
  subgraph Internet - public APIs
    N[NVD API]
    E[EPSS API]
    K[CISA KEV JSON]
  end
  B -- HTTP :8501 --> ST
  ST --> CORE
  CORE --> FS
  CORE -. scripts/fetch_intel.py .-> N
  CORE -.-> E
  CORE -.-> K
```

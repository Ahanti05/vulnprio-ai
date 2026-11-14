"""VulnPrio AI dashboard. Run with:  streamlit run app.py"""
from __future__ import annotations

import html
import json

import networkx as nx
import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from vulnprio import graph as ag
from vulnprio.analysis import run_analysis
from vulnprio.config import DEFAULT_WEIGHTS, ENTRY_NODE, SAMPLE_DIR
from vulnprio.loader import load_dataset, prepare_dataset
from vulnprio.ml.model import ExploitModel
from vulnprio.remediation import compare_strategies, evaluate_patch_set, greedy_fix_plan

st.set_page_config(page_title="VulnPrio AI", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

# --------------------------------------------------------------------------- design tokens
C = {"bg": "#0B1020", "panel": "#131A2E", "panel2": "#18213A", "line": "#26314F",
     "text": "#E6E9F2", "muted": "#8D97B5", "red": "#F43F5E", "amber": "#FBBF24",
     "blue": "#38BDF8", "violet": "#A78BFA", "green": "#34D399", "grey": "#94A3B8"}
BANDS = [(80, "P1 · Critical", C["red"]), (65, "P2 · High", C["amber"]),
         (50, "P3 · Medium", C["blue"]), (0, "P4 · Low", C["grey"])]

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
html, body, [class*="css"], .stMarkdown, .stText, button, input, textarea {{
  font-family: 'Inter', system-ui, sans-serif !important; }}
.block-container {{ padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1400px; }}
[data-testid="stSidebar"] {{ background: {C['panel']}; border-right: 1px solid {C['line']}; }}
h1, h2, h3 {{ letter-spacing: -0.02em; }}
.hero {{ background: radial-gradient(1200px 300px at 0% 0%, rgba(244,63,94,.18), transparent 60%),
         linear-gradient(135deg, {C['panel']} 0%, {C['panel2']} 100%);
  border: 1px solid {C['line']}; border-radius: 16px; padding: 22px 26px; margin-bottom: 18px; }}
.hero .eyebrow {{ color: {C['red']}; font-weight: 700; font-size: .78rem; letter-spacing: .14em;
  text-transform: uppercase; }}
.hero h1 {{ margin: 4px 0 6px; font-size: clamp(1.5rem, 3vw, 2.2rem); font-weight: 800; color: {C['text']}; }}
.hero p {{ color: {C['muted']}; margin: 0; font-size: .98rem; }}
.chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }}
.chip {{ border: 1px solid {C['line']}; background: rgba(255,255,255,.03); color: {C['text']};
  padding: 4px 10px; border-radius: 999px; font-size: .78rem; }}
.chip b {{ color: {C['green']}; }}
.kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px;
  margin: 6px 0 18px; }}
.kpi {{ background: {C['panel']}; border: 1px solid {C['line']}; border-radius: 14px; padding: 14px 16px;
  position: relative; overflow: hidden; }}
.kpi::before {{ content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: var(--accent); }}
.kpi .label {{ color: {C['muted']}; font-size: .74rem; font-weight: 600; letter-spacing: .06em;
  text-transform: uppercase; }}
.kpi .value {{ font-size: 1.85rem; font-weight: 800; margin-top: 4px; color: {C['text']};
  font-family: 'JetBrains Mono', monospace; }}
.kpi .sub {{ color: {C['muted']}; font-size: .8rem; margin-top: 2px; }}
.card {{ background: {C['panel']}; border: 1px solid {C['line']}; border-radius: 14px;
  padding: 16px 18px; margin-bottom: 14px; }}
.card h4 {{ margin: 0 0 10px; font-size: .95rem; color: {C['text']}; }}
.muted {{ color: {C['muted']}; font-size: .86rem; }}
.path {{ display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }}
.hop {{ background: {C['panel2']}; border: 1px solid {C['line']}; border-radius: 8px; padding: 5px 10px;
  font-family: 'JetBrains Mono', monospace; font-size: .82rem; }}
.hop.entry {{ border-color: {C['text']}; }}
.hop.target {{ border-color: {C['red']}; color: {C['red']}; font-weight: 600; }}
.arrow {{ color: {C['red']}; font-weight: 700; }}
.cve {{ font-size: .72rem; color: {C['muted']}; font-family: 'JetBrains Mono', monospace; }}
.band {{ display: inline-block; padding: 2px 9px; border-radius: 6px; font-size: .74rem; font-weight: 700; }}
.stTabs [data-baseweb="tab-list"] {{ gap: 4px; border-bottom: 1px solid {C['line']}; flex-wrap: wrap; }}
.stTabs [data-baseweb="tab"] {{ height: 40px; padding: 0 14px; border-radius: 10px 10px 0 0;
  font-weight: 600; }}
.stTabs [aria-selected="true"] {{ background: {C['panel']}; }}
[data-testid="stMetric"] {{ background: {C['panel']}; border: 1px solid {C['line']}; border-radius: 14px;
  padding: 12px 16px; }}
.footer {{ color: {C['muted']}; font-size: .78rem; border-top: 1px solid {C['line']}; padding-top: 14px;
  margin-top: 28px; }}
code {{ font-family: 'JetBrains Mono', monospace !important; }}
.steps {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;
  margin-bottom: 18px; }}
.step {{ background: {C['panel']}; border: 1px solid {C['line']}; border-radius: 14px; padding: 14px 16px; }}
.step .num {{ display: inline-flex; width: 26px; height: 26px; border-radius: 50%; align-items: center;
  justify-content: center; background: rgba(244,63,94,.15); color: {C['red']}; font-weight: 800;
  font-size: .85rem; margin-bottom: 8px; }}
.step .t {{ font-weight: 700; color: {C['text']}; margin-bottom: 4px; }}
.step .d {{ color: {C['muted']}; font-size: .85rem; line-height: 1.45; }}
.what {{ background: rgba(56,189,248,.07); border: 1px solid rgba(56,189,248,.25); border-radius: 10px;
  padding: 9px 14px; color: {C['text']}; font-size: .88rem; margin-bottom: 14px; }}
.what b {{ color: {C['blue']}; }}
</style>""", unsafe_allow_html=True)

PLOT = dict(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter", color=C["text"]), margin=dict(l=10, r=10, t=50, b=10),
            legend=dict(orientation="h", y=-0.2))
STRATEGY_COLORS = {"CVSS-only": C["grey"], "Contextual score": C["blue"],
                   "Graph-aware plan": C["red"]}


def style(fig):
    fig.update_layout(**PLOT)
    fig.update_xaxes(gridcolor=C["line"], zerolinecolor=C["line"])
    fig.update_yaxes(gridcolor=C["line"], zerolinecolor=C["line"])
    return fig


def band(score: float):
    for cut, label, color in BANDS:
        if score >= cut:
            return label, color
    return BANDS[-1][1], BANDS[-1][2]


def kpi(label, value, sub="", accent=C["blue"]):
    return (f'<div class="kpi" style="--accent:{accent}"><div class="label">{label}</div>'
            f'<div class="value">{value}</div><div class="sub">{sub}</div></div>')


def what(text: str):
    """One-line plain-English explanation shown at the top of each tab."""
    st.markdown(f'<div class="what"><b>What this shows:</b> {text}</div>', unsafe_allow_html=True)


GLOSSARY = """
| Term | Simple meaning |
|---|---|
| **Vulnerability / CVE** | A known security bug in software. Each one has an ID like *CVE-2021-44228*. |
| **CVSS** | A 0–10 score for how severe a bug is *in general*. It ignores where the bug is in **your** network. |
| **EPSS** | The predicted chance (0–1) that hackers will exploit the bug in the next 30 days. |
| **CISA KEV** | A US-government list of bugs that hackers are **already** exploiting. |
| **Asset** | Any computer or server in the company (web server, database, laptop…). |
| **Crown jewel ★** | A critical asset we must protect most, e.g. the customer database. |
| **Attack path** | A chain of hops a hacker could take, e.g. Internet → web server → database. |
| **Choke point** | An asset that many attack paths pass through. Securing it blocks many paths at once. |
| **Risk score (0–100)** | Our combined score. Higher means fix it sooner. |
| **AI exploit predictor** | A model trained on 54,000 real CVEs that guesses which bugs hackers will use. |
"""


def path_html(nodes, cves=None):
    parts = []
    for i, n in enumerate(nodes):
        cls = "entry" if i == 0 else ("target" if i == len(nodes) - 1 else "")
        parts.append(f'<span class="hop {cls}">{html.escape(n)}</span>')
        if i < len(nodes) - 1:
            parts.append('<span class="arrow">→</span>')
    cve_line = f'<div class="cve" style="margin-top:8px">via {", ".join(cves)}</div>' if cves else ""
    return f'<div class="path">{"".join(parts)}</div>{cve_line}'


# --------------------------------------------------------------------------- data
@st.cache_resource
def get_model():
    return ExploitModel.load()


@st.cache_data
def sample_dataset():
    return load_dataset(SAMPLE_DIR)


with st.sidebar:
    st.markdown("### 🛡️ VulnPrio AI")
    st.caption("Context-aware vulnerability prioritization & attack-path analysis")
    source = st.radio("Data source", ["Sample network (synthetic)", "Upload my CSVs"])
    dataset = None
    if source.startswith("Sample"):
        dataset = sample_dataset()
    else:
        up = {n: st.file_uploader(f"{n}.csv", type="csv", key=n)
              for n in ["assets", "edges", "findings", "cve_intel"]}
        if all(up.values()):
            dataset = prepare_dataset(*(pd.read_csv(up[n]) for n in
                                        ["assets", "edges", "findings", "cve_intel"]))
    model = get_model()
    use_ml = st.toggle("AI exploit model", value=model is not None, disabled=model is None,
                       help="Blend the AI exploit-likelihood into the exploit factor")
    with st.expander("⚙️ Advanced: risk weights"):
        st.caption("How much each factor counts in the score. Leave as-is if unsure.")
        weights = {k: st.slider(k.capitalize(), 0.0, 1.0, float(v), 0.05)
                   for k, v in DEFAULT_WEIGHTS.items()}
        st.caption("Normalised to sum to 1. Defaults are documented assumptions.")
    with st.expander("📖 Glossary: what do these words mean?"):
        st.markdown(GLOSSARY)
    st.divider()
    st.caption("B.Tech CSE Major Project · PVPIT Budhgaon · DBATU · 2026–27")

if dataset is None:
    st.info("Upload **assets.csv, edges.csv, findings.csv** and **cve_intel.csv** "
            "(formats in `data/sample`; build `cve_intel.csv` with `scripts/fetch_intel.py`).")
    st.stop()

analysis = run_analysis(dataset, weights, model if use_ml else None)
f = analysis.findings.copy()
m = analysis.metrics
f["priority"] = f["contextual_score"].map(lambda s: band(s)[0])
f["nvd"] = "https://nvd.nist.gov/vuln/detail/" + f["cve_id"]
snapshot = f["snapshot_date"].dropna().iloc[0] if "snapshot_date" in f and f["snapshot_date"].notna().any() else "n/a"

# --------------------------------------------------------------------------- hero
kev_n = int(f["in_kev"].sum())
st.markdown(f"""
<div class="hero">
  <div class="eyebrow">Vulnerability risk command center</div>
  <h1>What should we fix first, and why?</h1>
  <p>Ranks vulnerabilities by real-world context: exploitation evidence, an AI exploit predictor,
     asset importance, exposure and position on attack paths to critical systems.</p>
  <div class="chips">
    <span class="chip"><b>●</b> Live intel snapshot {snapshot}</span>
    <span class="chip">NVD · EPSS · CISA KEV</span>
    <span class="chip">AI model {'on' if analysis.model_used else 'off'}</span>
    <span class="chip">Synthetic demo network · real CVEs</span>
  </div>
</div>""", unsafe_allow_html=True)

COLS = {
    "contextual_rank": st.column_config.NumberColumn("Rank", width="small"),
    "cvss_rank": st.column_config.NumberColumn("CVSS rank", width="small"),
    "rank_shift": st.column_config.NumberColumn("Shift", help="+ = moved up vs CVSS-only", format="%+d"),
    "priority": st.column_config.TextColumn("Priority"),
    "finding_id": st.column_config.TextColumn("ID", width="small"),
    "hostname": st.column_config.TextColumn("Asset"),
    "nvd": st.column_config.LinkColumn("CVE", display_text=r"https://nvd\.nist\.gov/vuln/detail/(.*)"),
    "component": st.column_config.TextColumn("Component"),
    "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
    "attack_vector": st.column_config.TextColumn("Vector"),
    "epss": st.column_config.NumberColumn("EPSS", format="%.3f"),
    "in_kev": st.column_config.CheckboxColumn("KEV"),
    "ml_probability": st.column_config.ProgressColumn("AI exploit prob.", min_value=0, max_value=1, format="%.2f"),
    "f_path": st.column_config.ProgressColumn("Path share", min_value=0, max_value=1, format="%.2f"),
    "contextual_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%.1f"),
    "explanation": st.column_config.TextColumn("Why", width="large"),
}

tabs = st.tabs(["🏠 Overview", "📋 What to fix first", "🕸️ How attackers get in", "🧪 Try a fix",
                "✅ Best fix plan", "🤖 AI predictor", "🧹 Data check", "📖 How scoring works"])

# --------------------------------------------------------------------------- overview
with tabs[0]:
    st.markdown("""
<div class="steps">
  <div class="step"><div class="num">1</div><div class="t">Collect</div>
    <div class="d">Pull real bug data from NVD, EPSS and the CISA list of bugs hackers already use.</div></div>
  <div class="step"><div class="num">2</div><div class="t">Predict</div>
    <div class="d">Our AI, trained on 54,000 real bugs, estimates which ones hackers are likely to use.</div></div>
  <div class="step"><div class="num">3</div><div class="t">Map</div>
    <div class="d">Draw every route a hacker could take from the Internet to our most important systems.</div></div>
  <div class="step"><div class="num">4</div><div class="t">Rank & fix</div>
    <div class="d">Score every bug 0–100 with a plain reason, then plan the fixes that cut the most risk.</div></div>
</div>""", unsafe_allow_html=True)
    p1 = int((f["contextual_score"] >= 80).sum())
    st.markdown('<div class="kpis">' + "".join([
        kpi("Bugs found", len(f), f"across {len(dataset.assets)} computers", C["blue"]),
        kpi("Fix urgently (P1)", p1, "score 80 or more", C["red"]),
        kpi("Already exploited", kev_n, "on the CISA KEV list", C["amber"]),
        kpi("Attack routes", m["attack_paths"], "Internet → critical systems", C["violet"]),
        kpi("Critical systems at risk", f"{m['reachable_crown_jewels']}/{m['total_crown_jewels']}",
            "reachable by an attack route", C["red"]),
        kpi("Overall risk", f"{m['crown_jewel_risk']:.2f}", "0 = no way in; lower is better", C["green"]),
    ]) + "</div>", unsafe_allow_html=True)

    left, right = st.columns([3, 2], gap="large")
    with left:
        st.markdown("#### Fix First: top 10")
        st.dataframe(f.head(10)[["contextual_rank", "priority", "hostname", "nvd", "component",
                                 "contextual_score", "cvss_rank", "explanation"]],
                     column_config=COLS, hide_index=True, width="stretch")
    with right:
        if analysis.paths:
            p = analysis.paths[0]
            st.markdown(f'<div class="card"><h4>Most likely attack path · p = {p.probability:.3f}</h4>'
                        f'{path_html(p.nodes, p.cves)}</div>', unsafe_allow_html=True)
        cut = analysis.choke.loc[analysis.choke["in_min_cut"], "asset_id"].tolist()
        if cut:
            st.markdown(f'<div class="card"><h4>Choke points (minimum cut)</h4>'
                        f'<div class="path">{"".join(f"<span class=hop>{html.escape(c)}</span>" for c in cut)}</div>'
                        f'<div class="muted" style="margin-top:8px">Securing these assets disconnects the '
                        f'Internet from every crown jewel in the model.</div></div>', unsafe_allow_html=True)
        counts = f["priority"].value_counts().reindex([b[1] for b in BANDS], fill_value=0).reset_index()
        counts.columns = ["priority", "findings"]
        fig = px.bar(counts, x="findings", y="priority", orientation="h", color="priority",
                     color_discrete_map={b[1]: b[2] for b in BANDS}, title="Findings by priority")
        fig.update_layout(showlegend=False, height=260, yaxis_title=None)
        st.plotly_chart(style(fig), config={"displayModeBar": False})

    moved = f[f["rank_shift"].abs() >= 5].sort_values("rank_shift", key=abs, ascending=False)
    if not moved.empty:
        st.markdown("#### Where context disagrees with CVSS")
        st.caption("Findings that moved 5+ places compared with a CVSS-only ranking.")
        st.dataframe(moved[["hostname", "nvd", "cvss_score", "cvss_rank", "contextual_rank",
                            "rank_shift", "explanation"]],
                     column_config=COLS, hide_index=True, width="stretch")

# --------------------------------------------------------------------------- findings
with tabs[1]:
    what("every bug, ordered from <b>fix first</b> to <b>fix later</b>. The <b>Why</b> column gives the "
         "reason in plain words. <b>CVSS rank</b> shows where it would be if we used severity alone.")
    c1, c2, c3 = st.columns([2, 2, 1])
    pr = c1.multiselect("Priority", [b[1] for b in BANDS], default=[b[1] for b in BANDS])
    zones = sorted(f["zone"].dropna().unique())
    zn = c2.multiselect("Zone", zones, default=zones)
    kev_only = c3.toggle("KEV only")
    view = f[f["priority"].isin(pr) & f["zone"].isin(zn)]
    if kev_only:
        view = view[view["in_kev"]]
    cols = ["contextual_rank", "priority", "finding_id", "hostname", "nvd", "component",
            "cvss_score", "attack_vector", "epss", "in_kev"]
    if "ml_probability" in view:
        cols.append("ml_probability")
    cols += ["f_path", "contextual_score", "cvss_rank", "rank_shift", "explanation"]
    st.dataframe(view[cols], column_config=COLS, hide_index=True, width="stretch", height=480)
    st.download_button("⬇ Export Fix-First list (CSV)", view[cols].drop(columns=["nvd"])
                       .assign(cve_id=view["cve_id"]).to_csv(index=False), "fix_first.csv", "text/csv")
    fig = px.scatter(f, x="cvss_score", y="contextual_score", color="priority", symbol="in_kev",
                     color_discrete_map={b[1]: b[2] for b in BANDS},
                     hover_data=["finding_id", "hostname", "cve_id"],
                     labels={"cvss_score": "CVSS base score", "contextual_score": "Contextual risk score",
                             "in_kev": "In KEV"},
                     title="Same CVSS, different real risk")
    fig.update_traces(marker=dict(size=11, line=dict(width=1, color=C["bg"])))
    st.plotly_chart(style(fig), config={"displayModeBar": False})


# --------------------------------------------------------------------------- graph
def render_graph(g, edges_df, assets_df, highlight_path=None, choke=None, height=620):
    net = Network(height=f"{height}px", width="100%", directed=True, cdn_resources="remote",
                  bgcolor=C["bg"], font_color=C["text"])
    choke = set(choke or [])
    hp = set(zip(highlight_path, highlight_path[1:])) if highlight_path else set()
    flows = nx.DiGraph(list(zip(edges_df["source"], edges_df["target"])))
    flows.add_node(ENTRY_NODE)
    hops = nx.single_source_shortest_path_length(flows, ENTRY_NODE)
    far = max(hops.values(), default=0) + 1
    net.add_node(ENTRY_NODE, label="INTERNET", color={"background": C["text"], "border": C["text"]},
                 shape="box", font={"color": C["bg"], "face": "Inter", "size": 14}, level=0,
                 margin=10)
    for a in assets_df.to_dict("records"):
        n = a["asset_id"]
        col = C["red"] if a["crown_jewel"] else (C["amber"] if n in choke else C["blue"])
        net.add_node(n, label=n + (" ★" if a["crown_jewel"] else ""),
                     color={"background": col, "border": C["bg"], "highlight": col},
                     title=f"{a['role']}\ncriticality: {a['criticality']}\nexposure: {a['exposure']}",
                     shape="dot", size=20 if a["crown_jewel"] else 13, level=hops.get(n, far),
                     font={"color": C["text"], "face": "Inter", "size": 13})
    for e in edges_df.to_dict("records"):
        u, v = e["source"], e["target"]
        if g.has_edge(u, v):
            d = g[u][v]
            on = (u, v) in hp
            net.add_edge(u, v, color=C["amber"] if on else "rgba(244,63,94,0.75)", width=5 if on else 2,
                         title=f"Attack step p={d['prob']:.2f}\nvia {', '.join(d['cves'])}")
        else:
            net.add_edge(u, v, color="rgba(141,151,181,0.25)", dashes=True, width=1,
                         title=f"Network flow (port {e.get('port')}): no exploitable vulnerability")
    net.set_options(json.dumps({
        "layout": {"hierarchical": {"enabled": True, "direction": "LR", "levelSeparation": 190,
                                    "nodeSpacing": 70}},
        "physics": {"enabled": False},
        "edges": {"arrows": {"to": {"enabled": True, "scaleFactor": 0.6}},
                  "smooth": {"type": "cubicBezier", "forceDirection": "horizontal"}},
        "interaction": {"hover": True, "navigationButtons": True, "zoomView": True}}))
    page = net.generate_html()
    # Fit the whole network into view once drawn, and blend the frame into the dark theme
    page = page.replace(
        "network = new vis.Network(container, data, options);",
        "network = new vis.Network(container, data, options);"
        "network.once('afterDrawing', function () { network.fit({animation: false}); });")
    page = page.replace("</head>", f"<style>body{{margin:0;background:{C['bg']};}}"
                                   f".card{{border:none!important;background:{C['bg']}!important;}}"
                                   f"#mynetwork{{border:1px solid {C['line']}!important;border-radius:14px;}}"
                                   "</style></head>")
    components.html(page, height=height + 20)


with tabs[2]:
    what("a map of the company network. <b>Red arrows</b> are steps a hacker could take using a bug. "
         "Pick a route below to highlight it in <b>yellow</b>. Hover over any dot or arrow for details; "
         "scroll to zoom.")
    st.markdown('<span class="muted"><b style="color:#F43F5E">━</b> attack step &nbsp; '
                '<b style="color:#FBBF24">━</b> highlighted path &nbsp; '
                '<span style="opacity:.6">┄</span> network flow only &nbsp; '
                '<b style="color:#F43F5E">●</b> crown jewel ★ &nbsp; '
                '<b style="color:#FBBF24">●</b> choke point &nbsp; '
                '<b style="color:#38BDF8">●</b> asset</span>', unsafe_allow_html=True)
    paths = analysis.paths
    cut = set(analysis.choke.loc[analysis.choke["in_min_cut"], "asset_id"])
    sel = None
    if paths:
        labels = [f"#{i + 1} · p={p.probability:.3f} · " + " → ".join(p.nodes)
                  for i, p in enumerate(paths[:50])]
        choice = st.selectbox("Highlight an attack path (most likely first)", labels)
        chosen = paths[labels.index(choice)]
        sel = chosen.nodes
        st.markdown(f'<div class="card">{path_html(chosen.nodes, chosen.cves)}</div>',
                    unsafe_allow_html=True)
    else:
        st.success("No modelled attack path reaches a crown jewel.")
    render_graph(analysis.graph, dataset.edges, dataset.assets, sel, cut)
    c1, c2 = st.columns(2, gap="large")
    with c1:
        st.markdown("#### Attack paths")
        st.dataframe(pd.DataFrame([{"Path": " → ".join(p.nodes), "Probability": p.probability,
                                    "Hops": len(p.nodes) - 1, "CVEs": ", ".join(p.cves)}
                                   for p in paths[:20]]),
                     column_config={"Probability": st.column_config.ProgressColumn(
                         "Probability", min_value=0, max_value=1, format="%.3f")},
                     hide_index=True, width="stretch")
    with c2:
        st.markdown("#### Choke points")
        st.dataframe(analysis.choke, column_config={
            "share_of_paths": st.column_config.ProgressColumn("Share of paths", min_value=0,
                                                              max_value=1, format="%.2f"),
            "in_min_cut": st.column_config.CheckboxColumn("In min cut")},
            hide_index=True, width="stretch")

# --------------------------------------------------------------------------- what-if
with tabs[3]:
    what("pretend you fixed some bugs and instantly see how much safer the company becomes. "
         "Tip: try <b>F007 (mail-01)</b> first, it's the top route into the network.")
    options = (f["finding_id"] + " · " + f["hostname"] + " · " + f["cve_id"]).tolist()
    picked = st.multiselect("Findings to patch", options, placeholder="e.g. F007 · mail-01…")
    patched = {p.split(" · ")[0] for p in picked}
    after = evaluate_patch_set(dataset.assets, dataset.edges, f, patched)
    removed = (1 - after["crown_jewel_risk"] / m["crown_jewel_risk"]) * 100 if m["crown_jewel_risk"] else 0
    st.markdown('<div class="kpis">' + "".join([
        kpi("Attack paths", f"{m['attack_paths']} → {after['attack_paths']}", "before → after", C["violet"]),
        kpi("Crown jewels exposed", f"{m['reachable_crown_jewels']} → {after['reachable_crown_jewels']}",
            "before → after", C["red"]),
        kpi("Crown-jewel risk", f"{after['crown_jewel_risk']:.2f}", f"was {m['crown_jewel_risk']:.2f}", C["amber"]),
        kpi("Risk removed", f"{removed:.0f}%", f"{len(patched)} fix(es) applied", C["green"]),
    ]) + "</div>", unsafe_allow_html=True)
    if patched:
        g2 = ag.build_attack_graph(dataset.assets, dataset.edges, f, patched)
        render_graph(g2, dataset.edges, dataset.assets, height=520)

# --------------------------------------------------------------------------- plan + eval
with tabs[4]:
    what("the best order to fix bugs, and proof it works. The charts compare three ways of choosing "
         "fixes: by <b>CVSS only</b> (the usual way), by <b>our risk score</b>, and by our "
         "<b>graph-aware plan</b>. The line that drops fastest is the smartest strategy.")
    k = st.slider("Number of fixes to plan", 3, min(20, len(f)), 10)
    plan = greedy_fix_plan(dataset.assets, dataset.edges, f, k)
    comp = compare_strategies(dataset.assets, dataset.edges, f, k, greedy=plan)
    c1, c2 = st.columns(2, gap="large")
    fig = px.line(comp, x="fixes_applied", y="crown_jewel_risk", color="strategy", markers=True,
                  color_discrete_map=STRATEGY_COLORS,
                  labels={"fixes_applied": "Fixes applied", "crown_jewel_risk": "Crown-jewel risk"},
                  title="Remaining risk after N fixes (lower is better)")
    c1.plotly_chart(style(fig), config={"displayModeBar": False})
    fig2 = px.line(comp, x="fixes_applied", y="attack_paths", color="strategy", markers=True,
                   color_discrete_map=STRATEGY_COLORS,
                   labels={"fixes_applied": "Fixes applied", "attack_paths": "Attack paths"},
                   title="Remaining attack paths after N fixes")
    c2.plotly_chart(style(fig2), config={"displayModeBar": False})
    st.markdown("#### Graph-aware remediation plan")
    st.caption("Greedy optimiser: each step picks the fix that removes the most modelled crown-jewel risk.")
    st.dataframe(plan, column_config={
        "risk_removed_pct": st.column_config.ProgressColumn("Risk removed (cumulative)", min_value=0,
                                                            max_value=100, format="%.0f%%"),
        "contextual_score": st.column_config.NumberColumn("Score", format="%.1f")},
        hide_index=True, width="stretch")
    st.caption("Simulation on a synthetic network; it illustrates the method, not real-world performance.")

# --------------------------------------------------------------------------- AI model
with tabs[5]:
    what("how well our AI predicts which bugs hackers will actually use. It was tested on 2021 bugs it "
         "had never seen. Higher numbers are better; grey bars are the usual CVSS-only method.")
    if model is None:
        st.info("No model found. Run `python scripts/build_ml_dataset.py` then `python scripts/train_model.py`.")
    else:
        mt = model.metrics
        mm, cb = mt["model"], mt["cvss_only_baseline"]
        st.markdown('<div class="kpis">' + "".join([
            kpi("ROC-AUC", f"{mm['roc_auc']:.3f}", f"CVSS-only {cb['roc_auc']:.3f}", C["blue"]),
            kpi("PR-AUC", f"{mm['pr_auc']:.3f}", f"CVSS-only {cb['pr_auc']:.3f} · random "
                f"{mt['random_baseline_pr_auc']:.3f}", C["violet"]),
            kpi("Precision@100", f"{mm['precision_at_100'] * 100:.0f}%",
                f"CVSS-only {cb['precision_at_100'] * 100:.0f}%", C["green"]),
            kpi("Test CVEs", f"{mt['test_size']:,}", f"{mt['test_positives']} known exploited", C["amber"]),
        ]) + "</div>", unsafe_allow_html=True)
        st.markdown(f'<div class="card"><h4>How it works</h4><div class="muted">'
                    f'Predicts whether a CVE becomes a CISA KEV entry (known exploited) from its description '
                    f'(TF-IDF n-grams), CVSS metrics, CWE and vendor, using class-balanced logistic regression. '
                    f'Time-based split: {mt["split"]} · trained on {mt["train_size"]:,} CVEs.</div></div>',
                    unsafe_allow_html=True)
        cmp = pd.DataFrame({"metric": list(mm) * 2,
                            "value": list(mm.values()) + list(cb.values()),
                            "model": ["AI model"] * len(mm) + ["CVSS-only"] * len(cb)})
        c1, c2 = st.columns(2, gap="large")
        fig = px.bar(cmp, x="metric", y="value", color="model", barmode="group",
                     color_discrete_map={"AI model": C["red"], "CVSS-only": C["grey"]},
                     title="AI model vs CVSS-only on unseen CVEs")
        c1.plotly_chart(style(fig), config={"displayModeBar": False})
        tf = pd.DataFrame(model.top_features).head(15).iloc[::-1]
        fig2 = px.bar(tf, x="weight", y="feature", orientation="h", title="Strongest exploit signals learned")
        fig2.update_traces(marker_color=C["blue"])
        fig2.update_layout(height=460, yaxis_title=None)
        c2.plotly_chart(style(fig2), config={"displayModeBar": False})

# --------------------------------------------------------------------------- data quality
with tabs[6]:
    what("problems found while checking the input data (duplicates, missing values, mismatches) and "
         "how each was handled. Good results need clean data.")
    st.markdown("#### Validation report")
    if dataset.issues:
        for i in dataset.issues:
            st.markdown(f"- {i}")
    else:
        st.success("No data-quality issues found.")
    with st.expander(f"Assets ({len(dataset.assets)})"):
        st.dataframe(dataset.assets, hide_index=True, width="stretch")
    with st.expander(f"Network flows ({len(dataset.edges)})"):
        st.dataframe(dataset.edges, hide_index=True, width="stretch")

# --------------------------------------------------------------------------- about
with tabs[7]:
    what("the exact formula and rules behind every number in this app. Useful for the report and viva.")
    st.markdown("#### Glossary")
    st.markdown(GLOSSARY)
    w = {k: v / sum(weights.values()) for k, v in weights.items()} if sum(weights.values()) else weights
    st.markdown(f"""
#### Contextual risk score
`Score = 100 × ( {w['severity']:.2f}·Severity + {w['exploit']:.2f}·Exploit + {w['criticality']:.2f}·Criticality + {w['exposure']:.2f}·Exposure + {w['path']:.2f}·Path )`

| Factor | Meaning |
|---|---|
| Severity | CVSS base score ÷ 10 |
| Exploit | 1.0 if in CISA KEV, else 0.6 × EPSS percentile + 0.4 × AI percentile |
| Criticality | low 0.25 · medium 0.5 · high 0.75 · critical 1.0 |
| Exposure | internet 1.0 · internal 0.6 · isolated 0.3 |
| Path | share of modelled attack paths through the asset |

#### Attack-graph rule
An attack step **u → v** exists only if the network lets *u* reach *v* **and** *v* has an unpatched,
remotely exploitable CVE with high confidentiality or integrity impact. Edge weight = −log(p), so the
shortest path is the most likely path.

#### Data sources
NVD CVE API 2.0 · FIRST EPSS · CISA KEV (snapshot {snapshot}).

#### Scope and ethics
Defensive decision-support only: nothing is scanned or exploited. The demo network is synthetic.
A modelled path is a planning aid, not proof that an attack is possible.
""")

st.markdown('<div class="footer">VulnPrio AI · B.Tech CSE Major Project 2026–27 · Synthetic network, real CVE '
            'intelligence · For authorised, defensive use only.</div>', unsafe_allow_html=True)

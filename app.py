"""Streamlit dashboard: run with `streamlit run app.py`."""
from __future__ import annotations

import json

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

st.set_page_config(page_title="VulnPrio AI", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_model():
    return ExploitModel.load()


@st.cache_data
def sample_dataset():
    return load_dataset(SAMPLE_DIR)


# ----------------------------------------------------------------- sidebar
st.sidebar.title("🛡️ VulnPrio AI")
st.sidebar.caption("Context-aware vulnerability prioritization & attack-path analysis")

source = st.sidebar.radio("Data", ["Sample network (synthetic)", "Upload my CSVs"])
dataset = None
if source.startswith("Sample"):
    dataset = sample_dataset()
else:
    up = {n: st.sidebar.file_uploader(f"{n}.csv", type="csv", key=n)
          for n in ["assets", "edges", "findings", "cve_intel"]}
    if all(up.values()):
        dataset = prepare_dataset(*(pd.read_csv(up[n]) for n in
                                    ["assets", "edges", "findings", "cve_intel"]))
    else:
        st.info("Upload assets.csv, edges.csv, findings.csv and cve_intel.csv "
                "(see data/sample for the format; build cve_intel.csv with scripts/fetch_intel.py).")
        st.stop()

model = get_model()
use_ml = st.sidebar.toggle("Use AI exploit model", value=model is not None,
                           disabled=model is None,
                           help="Blend the ML exploit-likelihood into the exploit factor")

st.sidebar.subheader("Risk weights")
weights = {k: st.sidebar.slider(k.capitalize(), 0.0, 1.0, float(v), 0.05)
           for k, v in DEFAULT_WEIGHTS.items()}
st.sidebar.caption("Weights are normalised to sum to 1.")

analysis = run_analysis(dataset, weights, model if use_ml else None)
f = analysis.findings
m = analysis.metrics

st.warning("Demo data is a **synthetic** company network. CVE data (CVSS, EPSS, KEV) is real. "
           "Modelled attack paths are planning aids, not proof of exploitability.", icon="⚠️")

tabs = st.tabs(["📊 Overview", "📋 Ranked findings", "🕸️ Attack graph", "🧪 What-if fix",
                "✅ Fix plan & evaluation", "🤖 AI model", "🧹 Data quality"])

# ---------------------------------------------------------------- overview
with tabs[0]:
    c = st.columns(5)
    c[0].metric("Findings", len(f))
    c[1].metric("Assets", len(dataset.assets))
    c[2].metric("Attack paths", m["attack_paths"])
    c[3].metric("Crown jewels reachable", f"{m['reachable_crown_jewels']}/{m['total_crown_jewels']}")
    c[4].metric("Crown-jewel risk", m["crown_jewel_risk"],
                help="Sum over critical assets of the most likely attack-path probability")
    st.subheader("Fix First — top 10")
    top = f.head(10)[["contextual_rank", "cvss_rank", "finding_id", "hostname", "cve_id",
                      "component", "cvss_score", "in_kev", "contextual_score", "explanation"]]
    st.dataframe(top, hide_index=True, width="stretch")
    moved = f[f["rank_shift"].abs() >= 5]
    if not moved.empty:
        st.subheader("Biggest differences vs. CVSS-only ranking")
        st.dataframe(moved[["finding_id", "hostname", "cve_id", "cvss_score", "cvss_rank",
                            "contextual_rank", "rank_shift", "explanation"]]
                     .sort_values("rank_shift", key=abs, ascending=False),
                     hide_index=True, width="stretch")

# ---------------------------------------------------------------- findings
with tabs[1]:
    cols = ["contextual_rank", "cvss_rank", "rank_shift", "finding_id", "hostname", "cve_id",
            "component", "cvss_score", "attack_vector", "epss", "in_kev"]
    if "ml_probability" in f:
        cols.append("ml_probability")
    cols += ["f_path", "contextual_score", "explanation"]
    st.dataframe(f[cols], hide_index=True, width="stretch", height=520)
    fig = px.scatter(f, x="cvss_score", y="contextual_score", color="in_kev",
                     hover_data=["finding_id", "hostname", "cve_id"],
                     labels={"cvss_score": "CVSS base score", "contextual_score": "Contextual score",
                             "in_kev": "In CISA KEV"},
                     title="Same CVSS, different real risk: context changes the order")
    st.plotly_chart(fig)
    st.download_button("Download ranked findings (CSV)", f[cols].to_csv(index=False),
                       "fix_first.csv", "text/csv")


# ---------------------------------------------------------------- graph view
def render_graph(g, edges_df, assets_df, highlight_path=None, choke=None):
    net = Network(height="620px", width="100%", directed=True, cdn_resources="remote")
    choke = set(choke or [])
    hp = set(zip(highlight_path, highlight_path[1:])) if highlight_path else set()
    net.add_node(ENTRY_NODE, label="🌐 INTERNET", color="#222222", shape="box",
                 font={"color": "white"}, level=0)
    for a in assets_df.to_dict("records"):
        n = a["asset_id"]
        color = "#d62728" if a["crown_jewel"] else ("#ff7f0e" if n in choke else "#4c78a8")
        title = f"{a['role']} | criticality: {a['criticality']} | exposure: {a['exposure']}"
        net.add_node(n, label=n + (" 👑" if a["crown_jewel"] else ""), color=color, title=title,
                     shape="dot", size=22 if a["crown_jewel"] else 16)
    for e in edges_df.to_dict("records"):
        u, v = e["source"], e["target"]
        if g.has_edge(u, v):
            d = g[u][v]
            on = (u, v) in hp
            net.add_edge(u, v, color="#d62728" if on else "#e45756", width=4 if on else 2,
                         title=f"Attack step p={d['prob']:.2f} via {', '.join(d['cves'])}")
        else:
            net.add_edge(u, v, color="#cccccc", dashes=True, width=1,
                         title=f"Network flow only (port {e.get('port')}), no exploitable vuln")
    net.set_options(json.dumps({
        "layout": {"hierarchical": {"enabled": True, "direction": "LR",
                                    "sortMethod": "directed", "levelSeparation": 170,
                                    "nodeSpacing": 90}},
        "physics": {"enabled": False}, "edges": {"arrows": {"to": {"enabled": True}}},
        "interaction": {"hover": True}}))
    components.html(net.generate_html(), height=640)


with tabs[2]:
    st.caption("🔴 red edge = modelled attack step · grey dashed = network flow with no exploitable "
               "vulnerability · 👑 = crown jewel · 🟠 = choke point (minimum cut)")
    paths = analysis.paths
    cut = set(analysis.choke.loc[analysis.choke["in_min_cut"], "asset_id"])
    sel = None
    if paths:
        labels = [f"#{i + 1}  p={p.probability:.3f}  " + " → ".join(p.nodes)
                  for i, p in enumerate(paths[:50])]
        choice = st.selectbox("Highlight an attack path (most likely first)", labels)
        sel = paths[labels.index(choice)].nodes
    render_graph(analysis.graph, dataset.edges, dataset.assets, sel, cut)
    c1, c2 = st.columns(2)
    c1.subheader("Top attack paths")
    c1.dataframe(pd.DataFrame([{"path": " → ".join(p.nodes), "probability": round(p.probability, 4),
                                "hops": len(p.nodes) - 1, "CVEs": ", ".join(p.cves)}
                               for p in paths[:20]]), hide_index=True, width="stretch")
    c2.subheader("Choke points")
    c2.dataframe(analysis.choke, hide_index=True, width="stretch")

# ---------------------------------------------------------------- what-if
with tabs[3]:
    st.write("Pick findings to patch and see how the modelled attack surface changes.")
    options = f["finding_id"] + " · " + f["hostname"] + " · " + f["cve_id"]
    picked = st.multiselect("Findings to patch", options.tolist())
    patched = {p.split(" · ")[0] for p in picked}
    after = evaluate_patch_set(dataset.assets, dataset.edges, f, patched)
    c = st.columns(4)
    c[0].metric("Attack paths", after["attack_paths"], after["attack_paths"] - m["attack_paths"],
                delta_color="inverse")
    c[1].metric("Crown jewels reachable", after["reachable_crown_jewels"],
                after["reachable_crown_jewels"] - m["reachable_crown_jewels"], delta_color="inverse")
    c[2].metric("Crown-jewel risk", after["crown_jewel_risk"],
                round(after["crown_jewel_risk"] - m["crown_jewel_risk"], 4), delta_color="inverse")
    c[3].metric("Most likely path", after["max_path_probability"],
                round(after["max_path_probability"] - m["max_path_probability"], 4),
                delta_color="inverse")
    if patched:
        g2 = ag.build_attack_graph(dataset.assets, dataset.edges, f, patched)
        render_graph(g2, dataset.edges, dataset.assets)

# ---------------------------------------------------------------- plan + eval
with tabs[4]:
    k = st.slider("Number of fixes to plan", 3, min(20, len(f)), 10)
    plan = greedy_fix_plan(dataset.assets, dataset.edges, f, k)
    st.subheader("Graph-aware remediation plan (greedy)")
    st.caption("Each step picks the fix that removes the most modelled crown-jewel risk.")
    st.dataframe(plan, hide_index=True, width="stretch")
    comp = compare_strategies(dataset.assets, dataset.edges, f, k, greedy=plan)
    fig = px.line(comp, x="fixes_applied", y="crown_jewel_risk", color="strategy", markers=True,
                  title="Remaining crown-jewel risk after N fixes (lower is better)")
    st.plotly_chart(fig)
    fig2 = px.line(comp, x="fixes_applied", y="attack_paths", color="strategy", markers=True,
                   title="Remaining attack paths after N fixes")
    st.plotly_chart(fig2)
    st.caption("Simulation on synthetic data — results illustrate the method, they are not a "
               "claim about real networks.")

# ---------------------------------------------------------------- AI model
with tabs[5]:
    if model is None:
        st.info("No model found. Run `python scripts/build_ml_dataset.py` then "
                "`python scripts/train_model.py`.")
    else:
        mt = model.metrics
        st.write(f"**Task:** predict whether a CVE becomes a CISA KEV (known exploited) entry. "
                 f"**Split:** {mt['split']}.")
        st.write(f"Train: {mt['train_size']:,} CVEs ({mt['train_positives']} exploited) · "
                 f"Test: {mt['test_size']:,} CVEs ({mt['test_positives']} exploited)")
        st.dataframe(pd.DataFrame({"AI model": mt["model"], "CVSS-only": mt["cvss_only_baseline"]}),
                     width="stretch")
        st.caption(f"Random-guess PR-AUC = {mt['random_baseline_pr_auc']} (share of exploited CVEs)")
        st.subheader("What the model learned (top positive features)")
        st.dataframe(pd.DataFrame(model.top_features), hide_index=True, width="stretch")

# ---------------------------------------------------------------- data quality
with tabs[6]:
    if dataset.issues:
        for i in dataset.issues:
            st.write("• " + i)
    else:
        st.success("No data-quality issues found.")
    with st.expander("Assets"):
        st.dataframe(dataset.assets, hide_index=True, width="stretch")
    with st.expander("Network edges"):
        st.dataframe(dataset.edges, hide_index=True, width="stretch")

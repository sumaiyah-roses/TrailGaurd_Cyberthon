import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from trailguard import VARIANTS, analyze, load_logs
from trailguard.config import LABELS, STAGES
from trailguard.evaluate import evaluate
from trailguard.explain import explain
from trailguard.response import LADDER
from trailguard.synth import generate

st.set_page_config(page_title="TrailGuard", page_icon="🛡️", layout="wide")

INK, TEAL = "#14213d", "#0f766e"
LV = {"High": "#d93f4c", "Medium": "#e08a00", "Low": "#2f9e6e"}
ST = {"Probe": "#7c5cd6", "Breach": "#d93f4c", "Entrench": "#1f6fd1"}

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@500;700&family=Source+Sans+3:wght@400;600&display=swap');
html, body, [class*="css"] {{ font-family:'Source Sans 3',sans-serif; }}
h1,h2,h3,.tg-h {{ font-family:'Sora',sans-serif !important; letter-spacing:-.01em; }}
.block-container {{ padding-top:1.6rem; max-width:1250px; }}
.tg-hero {{ background:{INK}; color:#fff; border-radius:14px; padding:22px 28px; margin-bottom:18px; }}
.tg-hero h1 {{ color:#fff; margin:0; font-size:1.9rem; }}
.tg-hero p {{ color:#c9d4ea; margin:4px 0 0; }}
.tg-card {{ background:#fff; border:1px solid #e3e8f0; border-radius:10px; padding:14px 18px; }}
.tg-kpi b {{ font-family:'Sora'; font-size:1.7rem; color:{INK}; }}
.tg-kpi span {{ display:block; color:#5b6b86; font-size:.9rem; }}
.tg-badge {{ color:#fff; border-radius:6px; padding:2px 10px; font-weight:600; }}
.tg-trail {{ display:flex; align-items:stretch; gap:0; margin:6px 0 4px; }}
.tg-node {{ flex:1; border-radius:8px; padding:10px 12px; border:2px solid #e3e8f0; background:#fff; min-height:92px; }}
.tg-node.off {{ opacity:.45; border-style:dashed; }}
.tg-node h4 {{ margin:0 0 4px; font-family:'Sora'; font-size:1rem; }}
.tg-node small {{ color:#44536d; }}
.tg-arrow {{ align-self:center; font-size:1.4rem; padding:0 8px; color:#8a97ad; }}
.tg-rung {{ display:inline-block; border:1px solid #cfd8e6; border-radius:999px; padding:3px 12px; margin:2px 3px 2px 0; font-size:.88rem; color:#5b6b86; background:#fff; }}
.tg-rung.hit {{ background:{TEAL}; border-color:{TEAL}; color:#fff; font-weight:600; }}
.tg-rung.on {{ border-color:{TEAL}; color:{TEAL}; }}
.tg-head {{ border-left:5px solid; padding:12px 16px; background:#fff; border-radius:0 10px 10px 0; font-size:1.05rem; }}
.tg-step {{ margin:0 0 8px; padding-left:2px; }}
</style>""", unsafe_allow_html=True)

st.markdown("""<div class="tg-hero"><h1>🛡️ TrailGuard</h1>
<p>Account-takeover detection that shows its work: every alert comes with the attack chain, the log rows behind it, and what would change the verdict.</p></div>""", unsafe_allow_html=True)


@st.cache_data(show_spinner="Generating demo logs...")
def demo():
    return generate()


@st.cache_data(show_spinner="Analyzing...")
def run(df, key):
    return analyze(df, key)


@st.cache_data(show_spinner="Benchmarking four variants...")
def bench(df):
    return evaluate(df)


with st.sidebar:
    st.markdown("### Data")
    src = st.radio("Source", ["Demo (synthetic, labeled)", "Upload CSV / JSON"], label_visibility="collapsed")
    if src.startswith("Upload"):
        up = st.file_uploader("Auth logs", type=["csv", "json", "jsonl"])
        if not up:
            st.info("Columns needed: timestamp, user, ip, asn, is_vpn, country, device_id, result, event_type.")
            st.stop()
        try:
            df = load_logs(up)
        except Exception as e:
            st.error(f"Could not read this file: {e}")
            st.stop()
    else:
        df = demo()
    st.markdown("### Variant")
    key = st.selectbox("Detector", list(VARIANTS), index=2, format_func=lambda k: f"{k}: {VARIANTS[k].name}")
    st.caption("C is the full system. Switch to D to see what VPN-awareness is worth.")

incs = [i for i in run(df, key) if i.alerted]
incs.sort(key=lambda i: -i.score)
tab1, tab2, tab3 = st.tabs(["Incidents", "Benchmark", "How scoring works"])

with tab1:
    k = st.columns(4)
    for col, (n, label) in zip(k, [(len(df), "events analyzed"), (len(incs), "incidents alerted"),
                                   (sum(i.level == "High" for i in incs), "high risk"),
                                   (len({i.user for i in incs}), "users flagged")]):
        col.markdown(f'<div class="tg-card tg-kpi"><b>{n:,}</b><span>{label}</span></div>', unsafe_allow_html=True)
    if not incs:
        st.success("No incidents above the alert threshold for this data and variant.")
        st.stop()
    if not VARIANTS[key].correlate:
        st.caption("Variants A and B alert on single signals, so each incident is one signal. Switch to C for correlated attack chains.")

    st.write("")
    tbl = pd.DataFrame([dict(Incident=i.id, User=i.user, Level=i.level, Score=i.score, Chain=" → ".join(i.stages),
                             Signals=len(i.signals), Confidence=round(i.confidence * 100), Started=i.start) for i in incs])
    st.dataframe(tbl, hide_index=True, width="stretch", height=240, column_config={
        "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
        "Confidence": st.column_config.NumberColumn("Confidence", format="%d%%"),
        "Started": st.column_config.DatetimeColumn("Started", format="MMM D, HH:mm")})
    pick = st.selectbox("Open an incident", incs, format_func=lambda i: f"{i.id}  |  {i.user}  |  {i.level} {i.score}")
    ex = explain(pick)
    sc, cf = ex["score"], ex["cf"]

    left, right = st.columns([1, 2.2])
    with left:
        g = go.Figure(go.Indicator(mode="gauge+number", value=pick.score, number={"font": {"family": "Sora", "color": INK}},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": LV[pick.level], "thickness": .3},
                   "steps": [{"range": [0, 40], "color": "#e6f4ee"}, {"range": [40, 70], "color": "#fcefd6"},
                             {"range": [70, 100], "color": "#fbe1e3"}]}))
        g.update_layout(height=190, margin=dict(l=20, r=20, t=20, b=0), paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(g, width="stretch")
        st.markdown(f'<span class="tg-badge" style="background:{LV[pick.level]}">{pick.level} risk</span>&nbsp; {pick.user}',
                    unsafe_allow_html=True)
    with right:
        st.markdown(f'<div class="tg-head" style="border-color:{LV[pick.level]}"><b>Why this fired.</b> {ex["headline"]}</div>',
                    unsafe_allow_html=True)
        if ex["conf_note"]:
            st.warning(ex["conf_note"])
        rungs = "".join(f'<span class="tg-rung {"hit" if n == ex["rung"] else "on" if n < ex["rung"] else ""}">{r}</span>'
                        for n, r in enumerate(LADDER))
        st.markdown(f"**Recommended response: {ex['action']}**<br>{rungs}", unsafe_allow_html=True)
        if ex["action_note"]:
            st.caption(ex["action_note"])

    st.markdown("#### Attack chain")
    nodes = []
    for s in STAGES:
        ss = [x for x in pick.signals if x.stage == s]
        body = "<br>".join(f"{LABELS[x.name]} ({x.points:g})" for x in ss) or "not observed"
        nodes.append(f'<div class="tg-node {"" if ss else "off"}" style="border-color:{ST[s] if ss else "#e3e8f0"}">'
                     f'<h4 style="color:{ST[s]}">{s}</h4><small>{body}</small></div>')
    st.markdown('<div class="tg-trail">' + '<div class="tg-arrow">→</div>'.join(nodes) + "</div>", unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### How the score is calculated")
        for n, s in enumerate(ex["steps"], 1):
            st.markdown(f'<p class="tg-step"><b>{n}.</b> {s}</p>', unsafe_allow_html=True)
    with c2:
        st.markdown("#### What would change the verdict")
        names = [LABELS[n] for n, _, _ in cf.loo]
        vals = [v for _, v, _ in cf.loo]
        fig = go.Figure(go.Bar(x=vals, y=names, orientation="h", marker_color=[LV[l] for _, _, l in cf.loo],
                               text=[f"{lv} ({v})" for _, v, lv in cf.loo], textposition="outside"))
        fig.add_vline(x=40, line_dash="dot", line_color="#999")
        fig.add_vline(x=70, line_dash="dot", line_color="#999")
        fig.update_layout(height=60 + 38 * len(names), margin=dict(l=0, r=40, t=10, b=30), xaxis=dict(range=[0, 118], title="score without this signal"),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, width="stretch")
        st.caption(f"Minimal evidence for {pick.level}: {{{', '.join(cf.minimal)}}} on its own scores {cf.minimal_score}.")

    st.markdown("#### Signal ledger")
    led = pd.DataFrame(ex["table"])
    led["rows"] = led["rows"].map(lambda r: ", ".join(map(str, r)))
    led["counted"] = led["counted"].map({True: "yes", False: "repeat"})
    st.dataframe(led.rename(columns={"time": "Time", "stage": "Stage", "signal": "Signal", "base": "Base", "adjustments": "Adjustments",
                                     "points": "Points", "counted": "Counted", "rows": "Log rows", "detail": "Detail"}),
                 hide_index=True, width="stretch")
    with st.expander("Raw log rows cited by this incident"):
        cols = [c for c in ["row_id", "timestamp", "user", "ip", "asn", "is_vpn", "country", "device_id", "result", "event_type", "scenario"] if c in df]
        st.dataframe(df[df.row_id.isin(pick.rows)][cols], hide_index=True, width="stretch")

with tab2:
    if "attack_id" not in df:
        st.info("Benchmarking needs a labeled file with an attack_id column. Use the demo data to see it.")
    else:
        m, by = bench(df)
        st.markdown("Same logs, four detectors. Unit of measure: one user-day. Time-to-alert is the median from the first attack event.")
        show = m.rename(columns={"name": "Variant", "precision": "Precision", "recall": "Recall", "f1": "F1", "fpr": "False-positive rate",
                                 "median_tta_min": "Time to alert (min)", "attacks_caught": "Attacks caught", "false_alerts": "False alerts"})
        st.dataframe(show.style.format({"Precision": "{:.2f}", "Recall": "{:.2f}", "F1": "{:.2f}", "False-positive rate": "{:.3f}",
                                        "Time to alert (min)": "{:.1f}"}).background_gradient(subset=["F1"], cmap="Greens"),
                     width="stretch")
        fig = go.Figure()
        for met, col in [("precision", "#1f6fd1"), ("recall", "#2f9e6e"), ("f1", INK)]:
            fig.add_bar(name=met.capitalize() if met != "f1" else "F1", x=list(m.index), y=m[met], marker_color=col)
        fig.update_layout(barmode="group", height=320, margin=dict(l=0, r=0, t=10, b=0), yaxis=dict(range=[0, 1.05]),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", legend=dict(orientation="h", y=1.12))
        st.plotly_chart(fig, width="stretch")
        dF1, dFP = m.f1["C"] - m.f1["D"], m.false_alerts["D"] - m.false_alerts["C"]
        st.success(f"**Measured VPN benefit (C vs D):** F1 {m.f1['D']:.2f} → {m.f1['C']:.2f} (+{dF1:.2f}); "
                   f"{int(dFP)} fewer false alerts, FPR {m.fpr['D']:.3f} → {m.fpr['C']:.3f}.")
        st.markdown("**Recall by attack type**")
        st.dataframe(by.style.format("{:.0%}"), width="stretch")
        st.caption("Synthetic data, so absolute numbers are optimistic. The gaps between variants are the point. "
                   "`python -m trailguard evaluate --seeds 8` averages over several random datasets.")

with tab3:
    st.markdown(f"""
**1. Signals** are grouped into three kill-chain stages.

| Stage | Signals | What it means |
|---|---|---|
| Probe | failure burst, password spray | Someone is guessing credentials |
| Breach | fail-then-success, anomalous success, new country, impossible travel | A login got through, or looks wrong for this user |
| Entrench | MFA change, recovery change, password reset | The account is being locked in |

**2. Per-user surprise.** For every successful login, TrailGuard computes `-log2` of the smoothed frequency of this user's device, country, ASN and hour. Rare combinations add up to many bits. Under 12 bits is normal for a late-night shift or a new phone; above it, the login is anomalous.

**3. VPN-aware geo.** When the IP is VPN-flagged, country and ASN surprise is scaled by 0.2. When the device is already known, by 0.3. New-country and impossible-travel signals are skipped in both cases.

**4. Score.** Per stage: strongest signal plus half of the others. Then sum the stages and multiply by 1.0 / 1.25 / 1.5 for 1 / 2 / 3 stages present. Medium starts at 40, High at 70.

**5. Counterfactuals.** Remove each signal in turn and rescore, then search for the smallest set of signals that still reaches the same level.

**6. Response ladder.** {" → ".join(LADDER)}. Low confidence (under 50%, a cold-start user) caps the action at re-authentication.
""")

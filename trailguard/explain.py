"""Plain-language explanation of one incident's score."""
from .config import LABELS, PARAMS as P, STAGE_MULT
from .scoring import counterfactual, score
from .response import respond


def explain(inc):
    sc, cf = score(inc.signals), counterfactual(inc.signals)
    table = []
    for s in sorted(inc.signals, key=lambda s: s.ts):
        adj = "; ".join(f"x{f:g} {why}" for why, f in s.adjust) or "none"
        table.append(dict(time=s.ts, stage=s.stage, signal=s.name, base=round(s.base, 1), adjustments=adj,
                          points=s.points, counted=sc.counted[s.name] is s, rows=s.rows, detail=s.detail))
    drops = [f"Without {LABELS[n]} \u2192 {lv} ({v})" for n, v, lv in cf.loo if lv != sc.level]
    if not drops and cf.loo:
        n, v, lv = cf.loo[0]
        drops = [f"Without {LABELS[n]} \u2192 {lv} ({v}), still {lv}" if lv == sc.level else ""]
    headline = f"{sc.level} ({sc.total}). " + ". ".join(d for d in drops[:3] if d) + \
        f". Minimal evidence: {{{', '.join(cf.minimal)}}}."
    stage_txt = ", ".join(f"{st} {p}" for st, p in sc.stage_pts.items())
    steps = [
        "Each signal earns its base points, then context adjustments (VPN, known device, routine session) scale them.",
        f"Inside a kill-chain stage the strongest signal counts in full and the others at {int(P['stage_decay']*100)}%, "
        f"so overlapping evidence is not double counted: {stage_txt}.",
        f"{len(sc.stage_pts)} stage(s) present ({', '.join(sc.stage_pts)}) \u2192 multiplier x{STAGE_MULT.get(len(sc.stage_pts), 1)}.",
        f"Score = round({sc.raw} x {sc.mult}) = {sc.total} \u2192 {sc.level} (Medium \u2265 40, High \u2265 70).",
    ]
    conf_note = ""
    if inc.confidence < 0.5:
        conf_note = (f"Cold-start user: about {round(inc.confidence * P['full_conf_logins'])} prior logins, "
                     f"confidence {inc.confidence:.0%}. Baseline-based signals are weak or skipped.")
    rung, action, note = respond(sc.total, inc.confidence)
    return dict(score=sc, cf=cf, table=table, headline=headline, steps=steps, conf_note=conf_note,
                rung=rung, action=action, action_note=note)

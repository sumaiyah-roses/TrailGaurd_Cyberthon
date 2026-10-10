import pandas as pd
import pytest

from trailguard import analyze
from trailguard.baseline import Baseline
from trailguard.config import VARIANTS
from trailguard.evaluate import evaluate
from trailguard.explain import explain
from trailguard.response import respond
from trailguard.scoring import counterfactual, level_of, score
from trailguard.signals import Signal
from trailguard.synth import generate


def row(**k):
    d = dict(device_id="d1", country="IN", asn=1, timestamp=pd.Timestamp("2025-01-01 10:00"))
    return type("R", (), {**d, **k})


def test_surprise_unseen_higher_and_finite():
    b = Baseline()
    for _ in range(40):
        b.update(row())
    seen, new = b.surprise(row()), b.surprise(row(device_id="x", country="BR", asn=9))
    assert all(new[k] > seen[k] for k in ("device", "country", "asn", "hour") if k != "hour") and new["device"] < 20


def sig(name, pts, ts="2025-01-01 10:00"):
    return Signal("u", name, pd.Timestamp(ts), pts, [1], "")


def test_stage_multiplier_and_in_stage_decay():
    s = score([sig("fail_then_success", 25), sig("anomalous_success", 25)])   # one stage: 25 + 12.5
    assert s.stage_pts == {"Breach": 37.5} and s.total == 38 and s.mult == 1.0
    s2 = score([sig("fail_then_success", 25), sig("mfa_change", 25)])         # two stages x1.25
    assert s2.total == round(50 * 1.25) and s2.level == "Medium"
    s3 = score([sig("failure_burst", 30), sig("fail_then_success", 25), sig("mfa_change", 25)])
    assert s3.mult == 1.5 and s3.raw == 80 and s3.total == 100  # 120 capped at 100


def test_counterfactual_leave_one_out_and_minimal_set():
    sigs = [sig("fail_then_success", 25), sig("anomalous_success", 25), sig("new_country", 20), sig("mfa_change", 25)]
    full, cf = score(sigs), counterfactual(sigs)
    assert full.level == "High"
    loo = {n: lv for n, _, lv in cf.loo}
    assert loo["mfa_change"] == "Medium"
    assert level_of(score([full.counted[n] for n in cf.minimal]).total) == "High"
    assert len(cf.minimal) <= 3


def test_vpn_awareness_suppresses_geo_signals():
    rows, base = [], pd.Timestamp("2025-01-01 09:00")
    for i in range(12):
        rows.append(("2025-01-01 %02d:00" % (9 + i % 3), "IN", False, 100))
    rows.append(("2025-01-02 10:00", "BR", True, 900))
    rows.append(("2025-01-02 10:30", "DE", True, 901))
    df = pd.DataFrame([dict(timestamp=pd.Timestamp(t), user="u", ip="1.1.1.1", asn=a, is_vpn=v, country=c,
                            device_id="d1", result="success", event_type="login", row_id=i)
                       for i, (t, c, v, a) in enumerate(rows)])
    names = lambda k: {s.name for i in analyze(df, k) for s in i.signals}
    assert {"new_country", "impossible_travel"} <= names("D")
    assert not ({"new_country", "impossible_travel"} & names("C"))


def test_cold_start_lowers_confidence_and_caps_response():
    df = generate()
    cold = [i for i in analyze(df, "C") if i.alerted and i.confidence < 0.5]
    assert cold
    for i in cold:
        assert respond(i.score, i.confidence)[0] <= 2 and explain(i)["conf_note"]


def test_signals_cite_existing_rows():
    df = generate()
    ids = set(df.row_id)
    for i in analyze(df, "C"):
        assert all(s.rows and set(s.rows) <= ids for s in i.signals)


def test_headline_matches_format():
    df = generate()
    i = max(analyze(df, "C"), key=lambda x: x.score)
    h = explain(i)["headline"]
    assert h.startswith(f"{i.level} ({i.score}).") and "Minimal evidence: {" in h


def test_benchmark_ordering():
    m, _ = evaluate(generate())
    assert m.f1["C"] > m.f1["A"] and m.f1["C"] > m.f1["B"]
    assert m.f1["C"] > m.f1["D"] and m.fpr["C"] < m.fpr["D"]   # measured VPN benefit
    assert m.recall["C"] >= 0.9

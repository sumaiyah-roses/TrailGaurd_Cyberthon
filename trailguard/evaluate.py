"""Benchmark the four variants. scikit-learn is used for metrics only."""
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from .config import VARIANTS
from .pipeline import analyze


def evaluate(df, variants=VARIANTS):
    df = df.copy()
    df["is_atk"] = df.attack_id.fillna("").astype(str).ne("")
    df["date"] = df.timestamp.dt.date
    units = df.groupby(["user", "date"]).is_atk.any()          # unit = user-day
    y_true = units.values
    atk = df[df.is_atk].groupby("attack_id").agg(rows=("row_id", set), first=("timestamp", "min"), scen=("scenario", "first"))
    out, by_scen = [], {}
    for key, v in variants.items():
        alerted = [i for i in analyze(df, v) if i.alerted]
        pred = {(i.user, i.start.date()) for i in alerted}
        y_pred = np.array([k in pred for k in units.index])
        p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()
        ttas, caught = [], {}
        for aid, a in atk.iterrows():
            hits = [i.alert_time for i in alerted if set(i.rows) & a.rows]
            caught.setdefault(a.scen, []).append(bool(hits))
            if hits:
                ttas.append(max(0.0, (min(hits) - a["first"]).total_seconds() / 60))
        out.append(dict(variant=key, name=v.name, precision=p, recall=r, f1=f, fpr=fp / max(1, fp + tn),
                        median_tta_min=float(np.median(ttas)) if ttas else np.nan,
                        attacks_caught=f"{sum(sum(x) for x in caught.values())}/{len(atk)}", false_alerts=int(fp)))
        by_scen[key] = {s: np.mean(x) for s, x in caught.items()}
    return pd.DataFrame(out).set_index("variant"), pd.DataFrame(by_scen)

from pathlib import Path

import pandas as pd

from .config import VARIANTS
from .incidents import build_incidents
from .signals import detect

REQUIRED = ["timestamp", "user", "ip", "asn", "is_vpn", "country", "device_id", "result", "event_type"]


def load_logs(src):
    """Load CSV / JSON / JSONL (path or file-like with .name). Adds row_id if missing."""
    name = str(getattr(src, "name", src)).lower()
    if name.endswith(".jsonl"):
        df = pd.read_json(src, lines=True, convert_dates=False)
    elif name.endswith(".json"):
        df = pd.read_json(src, convert_dates=False)
    else:
        df = pd.read_csv(src)
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {', '.join(missing)}")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["is_vpn"] = df["is_vpn"].astype(str).str.lower().isin(["true", "1", "yes"])
    for c in ("user", "ip", "country", "device_id", "result", "event_type"):
        df[c] = df[c].astype(str)
    if "row_id" not in df.columns:
        df["row_id"] = range(len(df))
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def analyze(df, variant="C"):
    v = VARIANTS[variant] if isinstance(variant, str) else variant
    return build_incidents(detect(df, v), v)

"""Signal detectors: Probe, Breach, Entrench. Every signal cites its log row ids."""
from bisect import bisect_left
from dataclasses import dataclass, field

import pandas as pd

from .baseline import Baseline
from .config import PARAMS as P, STAGE_OF, WEIGHTS


@dataclass
class Signal:
    user: str
    name: str
    ts: pd.Timestamp
    base: float
    rows: list
    detail: str
    adjust: list = field(default_factory=list)   # [(reason, factor)]
    confidence: float = 1.0

    @property
    def stage(self):
        return STAGE_OF[self.name]

    @property
    def points(self):
        p = self.base
        for _, f in self.adjust:
            p *= f
        return round(p, 1)


def _mins(a, b):
    return (a - b).total_seconds() / 60


def _clusters(items, gap):
    out, cur = [], []
    for it in items:
        if cur and _mins(it[0], cur[-1][0]) > gap:
            out.append(cur)
            cur = []
        cur.append(it)
    if cur:
        out.append(cur)
    return out


def detect(df, v):
    sigs = _spray(df)
    for user, g in df.groupby("user", sort=False):
        sigs += _user_signals(user, g.sort_values("timestamp", kind="stable"), v)
    return sorted(sigs, key=lambda s: (s.user, s.ts))


def _spray(df):
    f = df[(df.event_type == "login") & (df.result == "fail")].sort_values("timestamp", kind="stable")
    out = []
    for ip, g in f.groupby("ip"):
        rows = list(g.itertuples())
        i = 0
        while i < len(rows):
            j = i
            while j < len(rows) and _mins(rows[j].timestamp, rows[i].timestamp) <= P["spray_min"]:
                j += 1
            win = rows[i:j]
            users = {r.user for r in win}
            if len(users) >= P["spray_users"]:
                seen, detect_ts = set(), win[-1].timestamp
                for r in win:
                    seen.add(r.user)
                    if len(seen) == P["spray_users"]:
                        detect_ts = r.timestamp
                        break
                for u in users:
                    ur = [r.row_id for r in win if r.user == u]
                    out.append(Signal(u, "password_spray", detect_ts, WEIGHTS["password_spray"], ur,
                                      f"IP {ip} failed against {len(users)} different accounts in {P['spray_min']} min"))
                i = j
            else:
                i += 1
    return out


def _user_signals(user, g, v):
    bl, sigs = Baseline(P["alpha"]), []
    succ_ts = sorted(r.timestamp for r in g.itertuples() if r.event_type == "login" and r.result == "success")
    conf = lambda ts: min(1.0, bisect_left(succ_ts, ts) / P["full_conf_logins"])

    fails = [(r.timestamp, r.row_id) for r in g.itertuples() if r.event_type == "login" and r.result == "fail"]
    for c in _clusters(fails, P["burst_gap_min"]):
        if len(c) >= P["burst_n"]:
            base = min(WEIGHTS["failure_burst"], 15 + 2.5 * len(c))
            ts = c[P["burst_n"] - 1][0]   # alert as soon as the burst threshold is reached
            sigs.append(Signal(user, "failure_burst", ts, base, [x[1] for x in c],
                               f"{len(c)} failed logins, each within {P['burst_gap_min']} min of the last", confidence=conf(ts)))

    recent, prev, last_ok = [], None, None
    T = P["surprise_T"]
    for r in g.itertuples():
        ts = r.timestamp
        if r.event_type == "login" and r.result == "fail":
            recent.append((ts, r.row_id))
            continue
        if r.event_type == "login":
            warm = bl.n >= P["warm_logins"]
            known_dev = bl.dev[r.device_id] > 0
            known_ctx = known_dev and bl.cty[r.country] > 0
            vpn_flag = bool(r.is_vpn)
            c, tot, parts, suspicious, gf = conf(ts), None, None, False, 1.0
            if warm:
                parts = bl.surprise(r)
                if v.vpn and vpn_flag:
                    gf = P["vpn_geo_discount"]
                elif v.vpn and known_dev:
                    gf = P["known_dev_geo_discount"]
                tot = parts["device"] + parts["hour"] + gf * (parts["country"] + parts["asn"])

            fs = [x for x in recent if _mins(ts, x[0]) <= P["fts_min"]]
            if len(fs) >= P["fts_fails"]:
                adj = []
                if v.surprise and warm and known_ctx and tot < T:
                    adj = [("known device and country, likely typos", 0.4)]
                sigs.append(Signal(user, "fail_then_success", ts, WEIGHTS["fail_then_success"],
                                   [x[1] for x in fs] + [r.row_id],
                                   f"{len(fs)} failures, then success from {r.country} on {r.device_id}", adj, c))
                suspicious |= not adj
            recent = []

            if v.surprise and warm and tot >= T:
                scale = min(1.0, 0.5 + (tot - T) / (2 * T))
                note = " (geo discounted: VPN/known device)" if gf < 1 else ""
                sigs.append(Signal(user, "anomalous_success", ts, WEIGHTS["anomalous_success"], [r.row_id],
                                   f"surprise {tot:.1f} bits: device {parts['device']:.1f}, hour {parts['hour']:.1f}, "
                                   f"country {parts['country']:.1f}, ASN {parts['asn']:.1f}{note}",
                                   [(f"surprise {tot:.1f} bits vs threshold {T:.0f}", round(scale, 2))], c))
                suspicious = True

            if warm and bl.cty[r.country] == 0 and not (v.vpn and (vpn_flag or known_dev)):
                sigs.append(Signal(user, "new_country", ts, WEIGHTS["new_country"], [r.row_id],
                                   f"first login from {r.country}", confidence=c))

            if prev and prev["country"] != r.country and _mins(ts, prev["ts"]) < P["travel_min"] \
                    and not (v.vpn and (vpn_flag or prev["vpn"] or known_dev)):
                sigs.append(Signal(user, "impossible_travel", ts, WEIGHTS["impossible_travel"], [prev["row"], r.row_id],
                                   f"{prev['country']} to {r.country} in {_mins(ts, prev['ts']):.0f} min", confidence=c))
                suspicious = True

            prev = dict(ts=ts, country=r.country, vpn=vpn_flag, row=r.row_id)
            last_ok = dict(ts=ts, tot=tot, known=known_dev, row=r.row_id)
            if not suspicious:   # never let a suspicious login poison the baseline
                bl.update(r)
        else:
            near = last_ok and _mins(ts, last_ok["ts"]) <= P["entrench_min"]
            adj = []
            if v.surprise and near and last_ok["known"] and last_ok["tot"] is not None and last_ok["tot"] < T / 2:
                adj = [("routine session: known device, low surprise", 0.5)]
            sigs.append(Signal(user, r.event_type, ts, WEIGHTS[r.event_type],
                               [r.row_id] + ([last_ok["row"]] if near else []),
                               f"{r.event_type.replace('_', ' ')} " + ("shortly after a login" if near else "with no recent login"),
                               adj, conf(ts)))
    return sigs

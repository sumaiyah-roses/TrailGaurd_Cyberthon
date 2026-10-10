"""Incident correlation: signals per user inside a time window merge into one incident."""
from dataclasses import dataclass

from .config import PARAMS as P
from .scoring import score, level_of


@dataclass
class Incident:
    id: str
    user: str
    signals: list
    score: int
    level: str
    start: object
    end: object
    alerted: bool
    alert_time: object
    confidence: float

    @property
    def rows(self):
        return sorted({r for s in self.signals for r in s.rows})

    @property
    def stages(self):
        return [st for st in ("Probe", "Breach", "Entrench") if any(s.stage == st for s in self.signals)]


def _groups(signals, correlate):
    if not correlate:
        return [[s] for s in sorted(signals, key=lambda s: (s.ts, s.user))]
    out, cur = [], []
    for s in sorted(signals, key=lambda s: (s.user, s.ts)):
        if cur and (s.user != cur[-1].user or (s.ts - cur[-1].ts).total_seconds() / 60 > P["incident_gap_min"]):
            out.append(cur)
            cur = []
        cur.append(s)
    if cur:
        out.append(cur)
    return out


def build_incidents(signals, v):
    incs = []
    for grp in _groups(signals, v.correlate):
        grp = sorted(grp, key=lambda s: s.ts)
        sc = score(grp)
        if v.correlate:
            alerted = sc.total >= P["alert_score"]
            alert_time = next((grp[k].ts for k in range(len(grp))
                               if score(grp[:k + 1]).total >= P["alert_score"]), None)
        else:
            alerted = grp[0].points >= P["signal_alert"]
            alert_time = grp[0].ts if alerted else None
        incs.append(Incident("", grp[0].user, grp, sc.total, level_of(sc.total), grp[0].ts, grp[-1].ts,
                             alerted, alert_time, min(s.confidence for s in grp)))
    incs.sort(key=lambda i: i.start)
    for n, i in enumerate(incs, 1):
        i.id = f"INC-{n:04d}"
    return incs

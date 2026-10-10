"""Stage-aware scoring and counterfactual explanations."""
from dataclasses import dataclass
from itertools import combinations

from .config import LEVELS, PARAMS as P, STAGES, STAGE_MULT

RANK = {"Low": 0, "Medium": 1, "High": 2}


def level_of(score):
    return next(name for name, lo in LEVELS if score >= lo)


@dataclass
class Score:
    total: int
    raw: float
    mult: float
    stage_pts: dict   # stage -> points after in-stage decay
    counted: dict     # signal name -> the strongest Signal of that type

    @property
    def level(self):
        return level_of(self.total)


def score(signals):
    counted = {}
    for s in signals:   # repeats of one signal type count once (the strongest)
        if s.name not in counted or s.points > counted[s.name].points:
            counted[s.name] = s
    stage_pts = {}
    for st in STAGES:
        pts = sorted((s.points for s in counted.values() if s.stage == st), reverse=True)
        if pts:   # strongest signal + 50% of the rest: overlapping evidence is not double counted
            stage_pts[st] = round(pts[0] + P["stage_decay"] * sum(pts[1:]), 1)
    mult = STAGE_MULT.get(len(stage_pts), 1.0)
    raw = sum(stage_pts.values())
    return Score(min(100, round(raw * mult)), round(raw, 1), mult, stage_pts, counted)


@dataclass
class Counterfactual:
    loo: list        # [(signal name, score without it, level without it)]
    minimal: tuple   # smallest signal-type set that still reaches the current level
    minimal_score: int


def counterfactual(signals):
    full = score(signals)
    names = list(full.counted)
    sc = lambda sub: score([full.counted[n] for n in sub]).total
    loo = [(n, sc([m for m in names if m != n])) for n in names]
    loo = [(n, s, level_of(s)) for n, s in sorted(loo, key=lambda x: x[1])]
    target = RANK[full.level]
    for k in range(1, len(names) + 1):
        ok = [c for c in combinations(names, k) if RANK[level_of(sc(c))] >= target]
        if ok:
            best = max(ok, key=sc)
            return Counterfactual(loo, best, sc(best))
    return Counterfactual(loo, tuple(names), full.total)

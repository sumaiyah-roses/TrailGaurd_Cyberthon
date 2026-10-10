import argparse
import json
from pathlib import Path

import pandas as pd

from .config import VARIANTS
from .evaluate import evaluate
from .explain import explain
from .pipeline import analyze, load_logs
from .synth import generate


def _inc_dict(i):
    e = explain(i)
    return dict(id=i.id, user=i.user, level=i.level, score=i.score, start=str(i.start), end=str(i.end),
                confidence=round(i.confidence, 2), stages=i.stages, headline=e["headline"], action=e["action"],
                signals=[dict(name=s.name, stage=s.stage, time=str(s.ts), points=s.points, rows=s.rows, detail=s.detail)
                         for s in i.signals])


def main(argv=None):
    p = argparse.ArgumentParser("trailguard", description="Explainable account-takeover detector")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write synthetic labeled logs")
    g.add_argument("--out", default="data/auth_logs.csv")
    g.add_argument("--users", type=int, default=50)
    g.add_argument("--seed", type=int, default=7)
    a = sub.add_parser("analyze", help="detect incidents in a log file")
    a.add_argument("--input", required=True)
    a.add_argument("--variant", default="C", choices=VARIANTS)
    a.add_argument("--top", type=int, default=10)
    a.add_argument("--json", help="write all alerted incidents to this JSON file")
    x = sub.add_parser("explain", help="show the full score calculation for one incident")
    x.add_argument("--input", required=True)
    x.add_argument("--incident", required=True, help="e.g. INC-0042")
    x.add_argument("--variant", default="C", choices=VARIANTS)
    e = sub.add_parser("evaluate", help="compare variants A-D on labeled data")
    e.add_argument("--input", help="labeled CSV (needs attack_id); default: fresh synthetic data")
    e.add_argument("--seeds", type=int, default=1, help="average over N synthetic seeds")
    args = p.parse_args(argv)

    if args.cmd == "generate":
        df = generate(args.users, seed=args.seed)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.out, index=False)
        print(f"Wrote {len(df)} events, {df.attack_id.ne('').sum()} attack rows -> {args.out}")
    elif args.cmd == "analyze":
        inc = [i for i in analyze(load_logs(args.input), args.variant) if i.alerted]
        inc.sort(key=lambda i: -i.score)
        print(f"{len(inc)} alerted incidents (variant {args.variant})")
        for i in inc[:args.top]:
            print(f"  {i.id}  {i.user:8s} {i.level:6s} {i.score:3d}  conf {i.confidence:.0%}  {' > '.join(i.stages)}")
        if args.json:
            Path(args.json).write_text(json.dumps([_inc_dict(i) for i in inc], indent=2))
            print(f"saved -> {args.json}")
    elif args.cmd == "explain":
        inc = next((i for i in analyze(load_logs(args.input), args.variant) if i.id == args.incident), None)
        if not inc:
            raise SystemExit(f"{args.incident} not found")
        ex = explain(inc)
        print(ex["headline"], f"\nUser {inc.user}, {inc.start} to {inc.end}, response: {ex['action']}")
        if ex["conf_note"]:
            print(ex["conf_note"])
        print("\nSignals")
        for r in ex["table"]:
            print(f"  {r['time']}  {r['stage']:8s} {r['signal']:18s} base {r['base']:5} -> {r['points']:5} "
                  f"{'' if r['counted'] else '(repeat, not counted) '}rows {r['rows']}\n      {r['detail']}; adjustments: {r['adjustments']}")
        print("\nHow the score is built")
        for n, s in enumerate(ex["steps"], 1):
            print(f"  {n}. {s}")
    else:
        if args.input:
            m, s = evaluate(load_logs(args.input))
        else:
            res = [evaluate(generate(seed=k + 7)) for k in range(args.seeds)]
            m = sum(r[0].drop(columns=["name", "attacks_caught"]) for r in res) / len(res)
            m.insert(0, "name", res[0][0]["name"])
        with pd.option_context("display.width", 200, "display.max_columns", 20):
            print(m.drop(columns=["attacks_caught"], errors="ignore").round(3).to_string())
        if "C" in m.index and "D" in m.index:
            print(f"\nMeasured VPN benefit (C vs D): F1 {m.f1['D']:.3f} -> {m.f1['C']:.3f}, "
                  f"FPR {m.fpr['D']:.3f} -> {m.fpr['C']:.3f}")


if __name__ == "__main__":
    main()

"""Synthetic labeled auth logs: ~50 users, injected attacks and hard benign cases."""
import numpy as np
import pandas as pd

HOME = ["IN", "US", "GB", "DE", "SG", "AU", "CA", "FR"]
ABROAD = ["BR", "RU", "NG", "VN", "RO", "UA", "ID", "TR", "PK", "EG", "KE", "AR", "PL", "TH", "MX", "ZA", "PH", "CO", "BD", "NL"]
ISP = [9829, 55836, 7922, 3320, 5089, 4755, 2856, 8151, 17488, 45609, 4134, 701]
HOST = [14061, 16276, 202425, 24940, 20473, 63949]
VPN = [9009, 60068, 212238, 62240, 396982, 141039]


def generate(n_users=50, days=21, seed=7):
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp("2025-03-03")
    rows, counter = [], [0]

    def ip(asn):
        return f"{asn % 190 + 10}.{asn % 97 + 3}.{rng.integers(0, 255)}.{rng.integers(1, 255)}"

    def add(ts, u, res, ev, asn, vpn, cty, dev, atk="", scen="benign", ip_=None):
        rows.append(dict(timestamp=ts, user=u, ip=ip_ or ip(asn), asn=asn, is_vpn=vpn, country=cty, device_id=dev,
                         result=res, event_type=ev, attack_id=atk, scenario=scen))

    def new_atk():
        counter[0] += 1
        return f"ATK-{counter[0]:03d}"

    ids = list(rng.permutation(n_users))
    vpn_users = set(ids[:round(.15 * n_users)])
    cold = set(ids[-4:])
    U = {}
    for i in range(n_users):
        u = f"user{i:02d}"
        U[u] = dict(home=HOME[rng.choice(8, p=[.4, .2, .1, .08, .07, .06, .05, .04])], asn=int(rng.choice(ISP)),
                    asn2=int(rng.choice(ISP)), center=float(np.clip(rng.normal(13, 2.5), 8, 18)),
                    vpn=i in vpn_users, cold=i in cold)
    users = list(U)
    warm_users = [u for u in users if not U[u]["cold"]]

    def home_login(u, ts, dev=None, res="success"):
        d = U[u]
        dev = dev or (f"{u}-laptop" if rng.random() < .8 else f"{u}-phone")
        if d["vpn"] and rng.random() < .85:
            add(ts, u, res, "login", int(rng.choice(VPN)), True, str(rng.choice(ABROAD + HOME)), dev)
        else:
            add(ts, u, res, "login", d["asn"] if rng.random() < .75 else d["asn2"], False, d["home"], dev)

    # baseline traffic
    for u, d in U.items():
        for day in range(18 if d["cold"] else 0, days):
            n = 2 if d["cold"] else int(rng.integers(2, 5) if (t0 + pd.Timedelta(days=day)).weekday() < 5 else rng.integers(1, 3))
            for _ in range(n):
                ts = t0 + pd.Timedelta(days=day, hours=int(rng.normal(d["center"], 2.2)) % 24, minutes=int(rng.integers(0, 60)))
                if rng.random() < .08 and not d["cold"]:
                    for k in range(int(rng.integers(1, 3))):
                        home_login(u, ts - pd.Timedelta(seconds=40 * (k + 1)), res="fail")
                home_login(u, ts)

    def when(day=None, hmin=0, hmax=21):
        day = int(rng.integers(14, 21)) if day is None else day
        return t0 + pd.Timedelta(days=day, hours=int(rng.integers(hmin, hmax)), minutes=int(rng.integers(0, 60)))

    def attacker(vpn):
        if vpn:
            return int(rng.choice(VPN)), True, str(rng.choice(ABROAD + HOME))
        return int(rng.choice(HOST)), False, str(rng.choice(ABROAD))

    def entrench(ts, u, a, atk, scen, asn, vpn, cty, dev, p=(.6, .85)):
        r = rng.random()
        ev = "mfa_change" if r < p[0] else "recovery_change" if r < p[1] else "password_reset"
        add(ts + pd.Timedelta(minutes=int(rng.integers(3, 13))), u, "success", ev, asn, vpn, cty, dev, atk, scen)

    def takeover(u, vpn, scen, day=None, cold_user=False):
        a, (asn, vp, cty) = new_atk(), attacker(vpn)
        ts, dev, aip = (when(day, 0, 22) if day is None else t0 + pd.Timedelta(days=day, hours=2, minutes=int(rng.integers(0, 50)))), f"atk-{a}", ip(asn)
        for _ in range(int(rng.integers(3, 7)) if rng.random() < .7 else 0):
            ts += pd.Timedelta(seconds=int(rng.integers(10, 40)))
            add(ts, u, "fail", "login", asn, vp, cty, dev, a, scen, aip)
        ts += pd.Timedelta(seconds=20)
        add(ts, u, "success", "login", asn, vp, cty, dev, a, scen, aip)
        if cold_user or rng.random() > .12:   # ~12% "quiet" takeovers never touch settings
            entrench(ts, u, a, a, scen, asn, vp, cty, dev)

    # --- attacks (last week) ---
    for u in rng.choice(warm_users, 6, replace=False):                       # brute force
        a, (asn, vp, cty) = new_atk(), attacker(rng.random() < .3)
        ts, aip = when(), ip(asn)
        for _ in range(int(rng.integers(15, 31))):
            ts += pd.Timedelta(seconds=int(rng.integers(2, 6)))
            add(ts, u, "fail", "login", asn, vp, cty, f"atk-{a}", a, "brute_force", aip)
        if rng.random() < .4:
            add(ts + pd.Timedelta(seconds=8), u, "success", "login", asn, vp, cty, f"atk-{a}", a, "brute_force", aip)
    for k in range(2):                                                        # password spray
        a, (asn, vp, cty) = new_atk(), attacker(k == 1)
        ts, aip = when(), ip(asn)
        victims = list(rng.choice(warm_users, 8, replace=False))
        for u in victims:
            for _ in range(int(rng.integers(1, 3))):
                ts += pd.Timedelta(seconds=int(rng.integers(20, 60)))
                add(ts, u, "fail", "login", asn, vp, cty, f"atk-{a}", a, "spray", aip)
        if k == 0:
            add(ts + pd.Timedelta(minutes=2), victims[0], "success", "login", asn, vp, cty, f"atk-{a}", a, "spray", aip)
    for u in rng.choice(warm_users, 8, replace=False):
        takeover(u, False, "takeover")
    for u in rng.choice(warm_users, 8, replace=False):
        takeover(u, True, "vpn_takeover")
    for u in rng.choice([u for u in users if U[u]['cold']], 2, replace=False):
        takeover(u, False, "cold_start_takeover", day=20, cold_user=True)

    # --- hard benign cases ---
    for u in rng.choice(warm_users, 6, replace=False):                       # travel with own laptop
        cty, asn, day = str(rng.choice(ABROAD)), int(rng.choice(ISP)), int(rng.integers(14, 19))
        for k in range(int(rng.integers(3, 6))):
            add(t0 + pd.Timedelta(days=day + k // 2, hours=9 + 5 * (k % 2), minutes=int(rng.integers(0, 50))), u,
                "success", "login", asn, False, cty, f"{u}-laptop", scen="benign_travel")
    for u in rng.choice(warm_users, 6, replace=False):                       # new phone + MFA enrolment
        d, ts, dev = U[u], None, None
        ts = t0 + pd.Timedelta(days=int(rng.integers(14, 21)), hours=int(d["center"]), minutes=int(rng.integers(0, 50)))
        add(ts, u, "success", "login", d["asn"], False, d["home"], f"{u}-phone2", scen="benign_new_phone")
        if rng.random() < .75:
            add(ts + pd.Timedelta(minutes=int(rng.integers(2, 7))), u, "success", "mfa_change", d["asn"], False, d["home"], f"{u}-phone2", scen="benign_new_phone")
    for u in rng.choice(warm_users, 6, replace=False):                       # late-night work
        d, day = U[u], int(rng.integers(14, 20))
        for k in range(int(rng.integers(2, 4))):
            add(t0 + pd.Timedelta(days=day, hours=1 + k, minutes=int(rng.integers(0, 50))), u, "success", "login",
                d["asn"], False, d["home"], f"{u}-laptop", scen="benign_late_night")
    for u in rng.choice(warm_users, 4, replace=False):                       # forgot password
        d, ts = U[u], when(hmin=9, hmax=18)
        for _ in range(int(rng.integers(3, 5))):
            ts += pd.Timedelta(seconds=int(rng.integers(15, 40)))
            add(ts, u, "fail", "login", d["asn"], False, d["home"], f"{u}-laptop", scen="benign_forgot_password")
        add(ts + pd.Timedelta(seconds=30), u, "success", "login", d["asn"], False, d["home"], f"{u}-laptop", scen="benign_forgot_password")
        add(ts + pd.Timedelta(minutes=2), u, "success", "password_reset", d["asn"], False, d["home"], f"{u}-laptop", scen="benign_forgot_password")

    df = pd.DataFrame(rows).sort_values("timestamp", kind="stable").reset_index(drop=True)
    df["row_id"] = range(len(df))
    return df

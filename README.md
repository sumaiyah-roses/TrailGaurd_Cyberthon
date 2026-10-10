# TrailGuard

**An explainable account-takeover detector.** It reconstructs the attack chain per account, scores each login against that user's own baseline (VPN-aware), and shows why every alert fired with counterfactual explanations.

> We combine kill-chain correlation, per-user surprise scoring with VPN-aware geo handling, and counterfactual explanations in a transparent, vendor-neutral analyzer, and quantify the gain over fixed rules.

## Run it

```bash
pip install -r requirements.txt
streamlit run app.py                                  # UI (demo data built in, or upload CSV/JSON)
python -m trailguard generate --out data/auth_logs.csv
python -m trailguard analyze  --input data/auth_logs.csv --top 10
python -m trailguard explain  --input data/auth_logs.csv --incident INC-0002
python -m trailguard evaluate --seeds 8               # variants A-D, averaged over 8 datasets
pytest
```

Input columns: `timestamp, user, ip, asn, is_vpn, country, device_id, result, event_type` (`login`, `mfa_change`, `recovery_change`, `password_reset`). `row_id` is optional and added if missing; every signal cites row ids.

## How a score is built

1. **Signals** fall into three stages: *Probe* (failure burst, password spray), *Breach* (fail-then-success, anomalous success, new country, impossible travel), *Entrench* (MFA, recovery, password change).
2. **Per-user surprise**: `-log2` of the smoothed frequency of this user's device, country, ASN and hour. A success above 12 bits is anomalous. Users with fewer than 5 prior logins skip baseline signals and get low confidence, which the alert states.
3. **VPN-aware geo**: VPN-flagged IP scales country/ASN surprise by 0.2, a known device by 0.3, and new-country / impossible-travel signals are skipped for either.
4. **Stage-aware score**: per stage, strongest signal + 50% of the others (overlap is not double counted); sum the stages, then multiply by 1.0 / 1.25 / 1.5 for 1 / 2 / 3 stages present. Medium ≥ 40, High ≥ 70, capped at 100.
5. **Counterfactuals**: leave-one-out rescoring plus the smallest signal set that still reaches the current level. Example from the demo data: *"High (100). Without failure burst → High (70), still High. Minimal evidence: {failure_burst, fail_then_success, mfa_change}."*
6. **Response ladder**: allow/log → step-up MFA → force re-auth → revoke sessions → reset password → open case. Confidence under 50% caps the action at re-auth.

All weights and thresholds live in `trailguard/config.py`.

## Measured results

Synthetic data: 50 users, 21 days, brute force, spray, takeover with MFA change, VPN attackers, cold-start takeovers, and hard benign cases (travel, new phone, late-night work, forgotten password, 15% habitual VPN users). Mean over 8 seeds, unit = user-day:

| Variant | Precision | Recall | F1 | FPR | Median time-to-alert |
|---|---|---|---|---|---|
| A  Fixed rules | 0.21 | 1.00 | 0.34 | 0.157 | 1.1 min |
| B  A + per-user surprise | 0.20 | 1.00 | 0.33 | 0.167 | 1.0 min |
| C  Full system | 0.98 | 0.96 | 0.97 | 0.001 | 2.6 min |
| D  C without VPN-awareness | 0.34 | 0.97 | 0.50 | 0.079 | 1.7 min |

**Measured VPN benefit (C vs D): F1 0.50 → 0.97, FPR 0.079 → 0.001.**

Read these numbers carefully:
- The data is synthetic and written by the same author as the detector, so absolute numbers are optimistic. The gaps between variants are the evidence, not the 0.97.
- B is slightly *worse* than A. Surprise scoring alone adds alerts and does not remove the habitual-VPN noise; the gain arrives once correlation and VPN-awareness are added.
- C pays for precision with a little recall (quiet takeovers that never touch settings, and cold-start users, are missed or only Medium) and about 1.5 extra minutes of time-to-alert.
- The highest benign incident under C scores 38 against an alert threshold of 40. That margin is thin; test on real logs before trusting it.
- Scores saturate at 100, so counterfactuals on very strong chains often read "still High".

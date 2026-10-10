"""All tunable knobs live here: signal weights, stages, thresholds, variants."""
from dataclasses import dataclass

# Base points per signal (failure_burst is dynamic: 15 + 2.5*failures, capped at this value)
WEIGHTS = {
    "failure_burst": 45, "password_spray": 40,
    "fail_then_success": 25, "anomalous_success": 25, "new_country": 20, "impossible_travel": 30,
    "mfa_change": 25, "recovery_change": 25, "password_reset": 20,
}
STAGE_OF = {
    "failure_burst": "Probe", "password_spray": "Probe",
    "fail_then_success": "Breach", "anomalous_success": "Breach",
    "new_country": "Breach", "impossible_travel": "Breach",
    "mfa_change": "Entrench", "recovery_change": "Entrench", "password_reset": "Entrench",
}
LABELS = {
    "failure_burst": "failure burst", "password_spray": "password spray",
    "fail_then_success": "fail-then-success", "anomalous_success": "anomalous success",
    "new_country": "new country", "impossible_travel": "impossible travel",
    "mfa_change": "MFA change", "recovery_change": "recovery change", "password_reset": "password reset",
}
STAGES = ["Probe", "Breach", "Entrench"]
STAGE_MULT = {1: 1.0, 2: 1.25, 3: 1.5}      # multiplier by number of kill-chain stages present
LEVELS = [("High", 70), ("Medium", 40), ("Low", 0)]

PARAMS = dict(
    alpha=0.5,               # additive smoothing for surprise
    surprise_T=12.0,         # bits of combined surprise that make a success "anomalous"
    warm_logins=5,           # below this the baseline is too thin for behavioural signals
    full_conf_logins=30,     # logins needed for 100% confidence
    burst_n=5, burst_gap_min=10,
    spray_users=5, spray_min=15,
    fts_fails=3, fts_min=15,
    entrench_min=30, travel_min=120,
    incident_gap_min=60,     # signals closer than this merge into one incident
    stage_decay=0.5,         # inside a stage: strongest signal + 50% of the rest
    signal_alert=18,         # variants A/B (no correlation): alert if one signal >= this
    alert_score=40,          # variants C/D: alert at Medium or above
    vpn_geo_discount=0.2,    # geo surprise multiplier when the IP is VPN-flagged
    known_dev_geo_discount=0.3,  # ... when the device is already known
)


@dataclass(frozen=True)
class Variant:
    key: str
    name: str
    surprise: bool   # per-user baseline surprise and context discounts
    correlate: bool  # kill-chain correlation + stage-aware scoring
    vpn: bool        # VPN-aware geo handling


VARIANTS = {
    "A": Variant("A", "Fixed rules", False, False, False),
    "B": Variant("B", "A + per-user surprise", True, False, False),
    "C": Variant("C", "Full system (B + kill chain + VPN-aware)", True, True, True),
    "D": Variant("D", "C with VPN-awareness off", True, True, False),
}

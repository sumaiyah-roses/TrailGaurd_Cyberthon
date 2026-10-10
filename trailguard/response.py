"""Response ladder: action depends on risk AND confidence."""
LADDER = ["Allow and log", "Step-up MFA", "Force re-authentication",
          "Revoke sessions", "Force password reset", "Open a case"]
CUTS = [0, 40, 55, 70, 85, 95]   # score needed for each rung


def respond(score, confidence):
    rung = max(i for i, c in enumerate(CUTS) if score >= c)
    note = ""
    if confidence < 0.5 and rung > 2:
        rung, note = 2, "Capped at re-authentication: too few prior logins to trust the baseline."
    elif confidence < 0.5 and rung > 0:
        note = "Low confidence: the user has little history, so this alert rests mostly on rules."
    return rung, LADDER[rung], note

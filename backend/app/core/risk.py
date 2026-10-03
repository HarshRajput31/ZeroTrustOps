from dataclasses import dataclass


@dataclass
class RiskResult:
    score: int
    level: str
    factors: list[str]


def calculate_risk(
    user_role: str,
    server_environment: str,
    requested_minutes: int,
    reason: str,
) -> RiskResult:
    score = 0
    factors = []

    role = user_role.upper()
    environment = server_environment.lower()
    reason_text = reason.strip()

    # User-role risk
    if role == "DEVELOPER":
        score += 10
        factors.append("Developer role")
    elif role == "VIEWER":
        score += 25
        factors.append("Viewer requesting elevated server access")
    elif role == "SECURITY_ADMIN":
        score += 5
        factors.append("Security administrator role")
    elif role == "ADMIN":
        score += 5
        factors.append("Administrator role")
    else:
        score += 30
        factors.append("Unknown or unrecognized role")

    # Environment risk
    if environment == "production":
        score += 30
        factors.append("Production environment")
    elif environment in {"staging", "pre-production"}:
        score += 15
        factors.append("Non-production but sensitive environment")
    else:
        score += 5
        factors.append("Lab/development environment")

    # Requested duration risk
    if requested_minutes <= 30:
        score += 5
        factors.append("Short access duration")
    elif requested_minutes <= 120:
        score += 15
        factors.append("Moderate access duration")
    elif requested_minutes <= 240:
        score += 25
        factors.append("Long access duration")
    else:
        score += 35
        factors.append("Very long access duration")

    # Reason quality
    if len(reason_text) < 20:
        score += 20
        factors.append("Very short access reason")
    elif len(reason_text) < 50:
        score += 10
        factors.append("Limited access justification")
    else:
        factors.append("Detailed access justification")

    # Cap score at 100
    score = min(score, 100)

    if score <= 30:
        level = "LOW"
    elif score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return RiskResult(
        score=score,
        level=level,
        factors=factors,
    )

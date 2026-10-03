from dataclasses import dataclass


@dataclass
class PolicyDecision:
    decision: str
    required_approver: str
    reason: str


def evaluate_policy(
    risk_score: int,
    server_environment: str,
    requested_minutes: int,
) -> PolicyDecision:

    environment = server_environment.lower()

    # Hard policy: excessive temporary access
    if requested_minutes > 480:
        return PolicyDecision(
            decision="DENY",
            required_approver="NONE",
            reason="Requested access exceeds the maximum temporary-access limit",
        )

    # High-risk production access requires administrator approval
    if risk_score > 60 and environment == "production":
        return PolicyDecision(
            decision="REQUIRE_ADMIN_APPROVAL",
            required_approver="ADMIN",
            reason="High-risk production access",
        )

    # High-risk access in any other environment
    if risk_score > 60:
        return PolicyDecision(
            decision="REQUIRE_SECURITY_APPROVAL",
            required_approver="SECURITY_ADMIN",
            reason="High-risk access request",
        )

    # Medium-risk access
    if risk_score > 30:
        return PolicyDecision(
            decision="REQUIRE_SECURITY_APPROVAL",
            required_approver="SECURITY_ADMIN",
            reason="Medium-risk access request",
        )

    # Low-risk request
    return PolicyDecision(
        decision="ALLOW_FOR_APPROVAL",
        required_approver="SECURITY_ADMIN",
        reason="Low-risk request",
    )

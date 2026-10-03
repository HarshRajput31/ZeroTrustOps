from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.core.policy import evaluate_policy
from app.core.rbac import require_roles
from app.core.risk import calculate_risk
from app.db.dependencies import get_db
from app.db.models import AccessRequest, Server, User
from app.schemas.access_request import (
    AccessRequestCreate,
    AccessRequestResponse,
)

router = APIRouter()


@router.post(
    "",
    response_model=AccessRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_access_request(
    data: AccessRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "ADMIN",
            "SECURITY_ADMIN",
            "DEVELOPER",
        )
    ),
):
    server = db.get(Server, data.server_id)

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    if not server.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server is inactive",
        )

    risk = calculate_risk(
        user_role=current_user.role,
        server_environment=server.environment,
        requested_minutes=data.requested_minutes,
        reason=data.reason,
    )

    policy = evaluate_policy(
        risk_score=risk.score,
        server_environment=server.environment,
        requested_minutes=data.requested_minutes,
    )

    if policy.decision == "DENY":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Access request denied by policy",
                "policy_reason": policy.reason,
                "risk_score": risk.score,
                "risk_level": risk.level,
            },
        )

    request = AccessRequest(
        user_id=current_user.id,
        server_id=server.id,
        reason=data.reason.strip(),
        status="PENDING",
        risk_score=risk.score,
        requested_minutes=data.requested_minutes,
        expires_at=None,
    )

    db.add(request)
    db.commit()
    db.refresh(request)

    return request


@router.get(
    "",
    response_model=list[AccessRequestResponse],
)
def list_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(AccessRequest)

    if current_user.role in {"ADMIN", "SECURITY_ADMIN"}:
        return (
            query
            .order_by(AccessRequest.id.desc())
            .all()
        )

    return (
        query
        .filter(AccessRequest.user_id == current_user.id)
        .order_by(AccessRequest.id.desc())
        .all()
    )


@router.get(
    "/{request_id}",
    response_model=AccessRequestResponse,
)
def get_access_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    request = db.get(AccessRequest, request_id)

    if request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )

    if (
        current_user.role not in {"ADMIN", "SECURITY_ADMIN"}
        and request.user_id != current_user.id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot view this access request",
        )

    return request


@router.post(
    "/{request_id}/approve",
    response_model=AccessRequestResponse,
)
def approve_access_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "ADMIN",
            "SECURITY_ADMIN",
        )
    ),
):
    request = db.get(AccessRequest, request_id)

    if request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )

    if request.status != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Request is already {request.status}",
        )

    server = db.get(Server, request.server_id)

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target server no longer exists",
        )

    request_user = db.get(User, request.user_id)

    if request_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requesting user no longer exists",
        )

    risk = calculate_risk(
        user_role=request_user.role,
        server_environment=server.environment,
        requested_minutes=request.requested_minutes,
        reason=request.reason,
    )

    policy = evaluate_policy(
        risk_score=risk.score,
        server_environment=server.environment,
        requested_minutes=request.requested_minutes,
    )

    # High-risk production access requires ADMIN
    if (
        policy.required_approver == "ADMIN"
        and current_user.role != "ADMIN"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This request requires ADMIN approval",
        )

    if policy.decision == "DENY":
        request.status = "REJECTED"
        request.expires_at = None

        db.commit()
        db.refresh(request)

        return request

    now = datetime.now(timezone.utc)

    request.risk_score = risk.score
    request.status = "APPROVED"
    request.expires_at = now + timedelta(
        minutes=request.requested_minutes
    )

    db.commit()
    db.refresh(request)

    return request


@router.post(
    "/{request_id}/reject",
    response_model=AccessRequestResponse,
)
def reject_access_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "ADMIN",
            "SECURITY_ADMIN",
        )
    ),
):
    request = db.get(AccessRequest, request_id)

    if request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )

    if request.status != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Request is already {request.status}",
        )

    request.status = "REJECTED"
    request.expires_at = None

    db.commit()
    db.refresh(request)

    return request

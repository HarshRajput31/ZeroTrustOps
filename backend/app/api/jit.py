from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.core.audit import write_audit_log
from app.core.jit import grant_ssh_key, revoke_ssh_key
from app.db.dependencies import get_db
from app.db.models import AccessRequest, AuditLog, SSHKey, User

router = APIRouter()


@router.post("/access-requests/{request_id}/activate")
def activate_jit_access(
    request_id: int,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    access_request = db.get(AccessRequest, request_id)

    if access_request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )

    if access_request.status != "APPROVED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access request must be APPROVED before JIT activation",
        )

    if (
        current_user.id != access_request.user_id
        and current_user.role not in {"ADMIN", "SECURITY_ADMIN"}
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot activate this access request",
        )

    now = datetime.now(timezone.utc)

    if access_request.expires_at is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Approved request has no expiration time",
        )

    if access_request.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access request has already expired",
        )

    user = db.get(User, access_request.user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requesting user not found",
        )

    ssh_key = (
        db.query(SSHKey)
        .filter(
            SSHKey.user_id == user.id,
            SSHKey.is_active.is_(True),
        )
        .order_by(SSHKey.id.desc())
        .first()
    )

    if ssh_key is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active SSH key is registered for this user",
        )

    if user.username != "developer01":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No JIT Linux account mapping exists for this user",
        )

    try:
        grant_ssh_key(
            linux_username=user.username,
            public_key=ssh_key.public_key,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    source_ip = (
        http_request.client.host
        if http_request.client
        else None
    )

    write_audit_log(
        db,
        user_id=current_user.id,
        action="JIT_ACCESS_GRANTED",
        resource=f"access_request:{access_request.id}",
        source_ip=source_ip,
        details=(
            f"JIT SSH access granted to {user.username}; "
            f"ssh_key_id={ssh_key.id}; "
            f"expires_at={access_request.expires_at.isoformat()}"
        ),
    )

    db.commit()

    return {
        "status": "JIT_ACCESS_ACTIVE",
        "request_id": access_request.id,
        "username": user.username,
        "ssh_key_id": ssh_key.id,
        "expires_at": access_request.expires_at,
        "message": "Temporary SSH authorization granted",
    }


@router.post("/access-requests/{request_id}/revoke")
def revoke_jit_access(
    request_id: int,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    access_request = db.get(AccessRequest, request_id)

    if access_request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )

    if (
        current_user.id != access_request.user_id
        and current_user.role not in {"ADMIN", "SECURITY_ADMIN"}
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot revoke this access request",
        )

    user = db.get(User, access_request.user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requesting user not found",
        )

    ssh_key = (
        db.query(SSHKey)
        .filter(
            SSHKey.user_id == user.id,
            SSHKey.is_active.is_(True),
        )
        .order_by(SSHKey.id.desc())
        .first()
    )

    if ssh_key is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active SSH key found",
        )

    if user.username != "developer01":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No JIT Linux account mapping exists for this user",
        )

    try:
        revoke_ssh_key(
            linux_username=user.username,
            public_key=ssh_key.public_key,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    source_ip = (
        http_request.client.host
        if http_request.client
        else None
    )

    previous_status = access_request.status

    if access_request.status == "APPROVED":
        access_request.status = "REVOKED"
        access_request.expires_at = None

    write_audit_log(
        db,
        user_id=current_user.id,
        action="JIT_ACCESS_REVOKED",
        resource=f"access_request:{access_request.id}",
        source_ip=source_ip,
        details=(
            f"JIT SSH access revoked for {user.username}; "
            f"ssh_key_id={ssh_key.id}; "
            f"previous_status={previous_status}"
        ),
    )

    db.commit()

    return {
        "status": "JIT_ACCESS_REVOKED",
        "request_id": access_request.id,
        "username": user.username,
        "ssh_key_id": ssh_key.id,
        "message": "Temporary SSH authorization revoked",
    }


@router.get("/audit-check")
def audit_check(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):
    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == current_user.id
        )
        .order_by(AuditLog.id.desc())
        .limit(20)
        .all()
    )

    return [
        {
            "id": log.id,
            "action": log.action,
            "resource": log.resource,
            "source_ip": log.source_ip,
            "details": log.details,
            "created_at": log.created_at,
        }
        for log in logs
    ]

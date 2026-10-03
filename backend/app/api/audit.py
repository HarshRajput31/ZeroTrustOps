from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.core.rbac import require_roles
from app.db.dependencies import get_db
from app.db.models import AuditLog, User

router = APIRouter()


@router.get("")
def list_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "ADMIN",
            "SECURITY_ADMIN",
        )
    ),
):
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(200)
        .all()
    )

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource": log.resource,
            "source_ip": log.source_ip,
            "details": log.details,
            "created_at": log.created_at,
        }
        for log in logs
    ]

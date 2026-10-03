from sqlalchemy.orm import Session

from app.db.models import AuditLog


def write_audit_log(
    db: Session,
    *,
    user_id: int | None,
    action: str,
    resource: str,
    source_ip: str | None = None,
    details: str | None = None,
) -> None:
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        source_ip=source_ip,
        details=details,
    )

    db.add(log)

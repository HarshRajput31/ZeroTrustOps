from datetime import datetime, timezone
from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session as DBSession

from app.api.auth import get_current_user
from app.core.audit import write_audit_log
from app.db.dependencies import get_db
from app.db.models import Server, Session as SessionModel, User
from app.schemas.session import SessionCreate, SessionResponse

router = APIRouter()


@router.post(
    "",
    response_model=SessionResponse,
    status_code=status.HTTP_201_CREATED,
)
def start_session(
    data: SessionCreate,
    db: DBSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
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

    try:
        source_ip = str(ip_address(data.source_ip.strip()))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid source IP address",
        )

    active_session = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == current_user.id,
            SessionModel.server_id == server.id,
            SessionModel.status == "ACTIVE",
        )
        .first()
    )

    if active_session:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An active session already exists for this user and server",
        )

    session = SessionModel(
        user_id=current_user.id,
        server_id=server.id,
        source_ip=source_ip,
        started_at=datetime.now(timezone.utc),
        ended_at=None,
        status="ACTIVE",
    )

    db.add(session)

    db.flush()

    write_audit_log(
        db,
        user_id=current_user.id,
        action="SESSION_STARTED",
        resource=f"session:{session.id}",
        source_ip=source_ip,
        details=(
            f"Session started; server_id={server.id}"
        ),
    )

    db.commit()
    db.refresh(session)

    return session


@router.get(
    "",
    response_model=list[SessionResponse],
)
def list_sessions(
    db: DBSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(SessionModel)

    if current_user.role in {"ADMIN", "SECURITY_ADMIN"}:
        return (
            query
            .order_by(SessionModel.id.desc())
            .limit(200)
            .all()
        )

    return (
        query
        .filter(SessionModel.user_id == current_user.id)
        .order_by(SessionModel.id.desc())
        .limit(200)
        .all()
    )


@router.get(
    "/{session_id}",
    response_model=SessionResponse,
)
def get_session(
    session_id: int,
    db: DBSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = db.get(SessionModel, session_id)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if (
        session.user_id != current_user.id
        and current_user.role not in {"ADMIN", "SECURITY_ADMIN"}
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot access this session",
        )

    return session


@router.post(
    "/{session_id}/end",
    response_model=SessionResponse,
)
def end_session(
    session_id: int,
    db: DBSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = db.get(SessionModel, session_id)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if (
        session.user_id != current_user.id
        and current_user.role not in {"ADMIN", "SECURITY_ADMIN"}
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot end this session",
        )

    if session.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session is already {session.status}",
        )

    session.status = "ENDED"
    session.ended_at = datetime.now(timezone.utc)

    write_audit_log(
        db,
        user_id=current_user.id,
        action="SESSION_ENDED",
        resource=f"session:{session.id}",
        source_ip=session.source_ip,
        details=(
            f"Session ended; server_id={session.server_id}"
        ),
    )

    db.commit()
    db.refresh(session)

    return session

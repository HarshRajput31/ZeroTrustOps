from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.core.rbac import require_roles
from app.db.dependencies import get_db
from app.db.models import Server, User
from app.schemas.server import (
    ServerCreate,
    ServerResponse,
    ServerUpdate,
)

router = APIRouter()


@router.post(
    "",
    response_model=ServerResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_server(
    data: ServerCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("ADMIN")),
):
    existing = (
        db.query(Server)
        .filter(Server.ip_address == str(data.ip_address))
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A server with this IP address already exists",
        )

    server = Server(
        name=data.name,
        hostname=data.hostname,
        ip_address=str(data.ip_address),
        ssh_port=data.ssh_port,
        environment=data.environment,
        is_active=True,
    )

    db.add(server)
    db.commit()
    db.refresh(server)

    return server


@router.get(
    "",
    response_model=list[ServerResponse],
)
def list_servers(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Server)
        .order_by(Server.id.asc())
        .all()
    )


@router.get(
    "/{server_id}",
    response_model=ServerResponse,
)
def get_server(
    server_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    server = db.get(Server, server_id)

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    return server


@router.patch(
    "/{server_id}",
    response_model=ServerResponse,
)
def update_server(
    server_id: int,
    data: ServerUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("ADMIN")),
):
    server = db.get(Server, server_id)

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    updates = data.model_dump(exclude_unset=True)

    if "ip_address" in updates and updates["ip_address"] is not None:
        updates["ip_address"] = str(updates["ip_address"])

    if "ip_address" in updates:
        existing = (
            db.query(Server)
            .filter(
                Server.ip_address == updates["ip_address"],
                Server.id != server_id,
            )
            .first()
        )

        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Another server already uses this IP address",
            )

    for field, value in updates.items():
        setattr(server, field, value)

    db.commit()
    db.refresh(server)

    return server


@router.delete(
    "/{server_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_server(
    server_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("ADMIN")),
):
    server = db.get(Server, server_id)

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    db.delete(server)
    db.commit()

    return None

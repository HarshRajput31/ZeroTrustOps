import base64
import hashlib

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.core.rbac import require_roles
from app.db.dependencies import get_db
from app.db.models import SSHKey, User
from app.schemas.ssh_key import SSHKeyCreate, SSHKeyResponse

router = APIRouter()


def calculate_fingerprint(public_key: str) -> str:
    parts = public_key.strip().split()

    if len(parts) < 2:
        raise ValueError("Invalid SSH public key format")

    key_type = parts[0]
    encoded_key = parts[1]

    try:
        key_blob = base64.b64decode(
            encoded_key,
            validate=True,
        )
    except Exception as exc:
        raise ValueError(
            "Invalid SSH public key encoding"
        ) from exc

    if not key_blob:
        raise ValueError("Empty SSH key data")

    # Confirm the key type exists in the SSH key blob.
    # This helps reject arbitrary base64 strings.
    key_type_bytes = key_type.encode()

    if key_type_bytes not in key_blob:
        raise ValueError("Invalid SSH public key")

    digest = hashlib.sha256(key_blob).digest()

    fingerprint = base64.b64encode(
        digest
    ).decode().rstrip("=")

    return f"SHA256:{fingerprint}"


@router.post(
    "",
    response_model=SSHKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_ssh_key(
    data: SSHKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    public_key = data.public_key.strip()

    try:
        fingerprint = calculate_fingerprint(public_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    existing = (
        db.query(SSHKey)
        .filter(
            SSHKey.user_id == current_user.id,
            SSHKey.fingerprint == fingerprint,
        )
        .first()
    )

    if existing:
        if existing.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="SSH key already registered",
            )

        existing.public_key = public_key
        existing.name = data.name.strip()
        existing.is_active = True

        db.commit()
        db.refresh(existing)

        return existing

    ssh_key = SSHKey(
        user_id=current_user.id,
        name=data.name.strip(),
        public_key=public_key,
        fingerprint=fingerprint,
        is_active=True,
    )

    db.add(ssh_key)
    db.commit()
    db.refresh(ssh_key)

    return ssh_key


@router.get(
    "",
    response_model=list[SSHKeyResponse],
)
def list_ssh_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(SSHKey)

    if current_user.role in {
        "ADMIN",
        "SECURITY_ADMIN",
    }:
        return (
            query
            .order_by(SSHKey.id.desc())
            .all()
        )

    return (
        query
        .filter(SSHKey.user_id == current_user.id)
        .order_by(SSHKey.id.desc())
        .all()
    )


@router.get(
    "/{key_id}",
    response_model=SSHKeyResponse,
)
def get_ssh_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ssh_key = db.get(SSHKey, key_id)

    if ssh_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSH key not found",
        )

    if (
        ssh_key.user_id != current_user.id
        and current_user.role not in {
            "ADMIN",
            "SECURITY_ADMIN",
        }
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot access this SSH key",
        )

    return ssh_key


@router.delete(
    "/{key_id}",
    response_model=SSHKeyResponse,
)
def revoke_ssh_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ssh_key = db.get(SSHKey, key_id)

    if ssh_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSH key not found",
        )

    if (
        ssh_key.user_id != current_user.id
        and current_user.role not in {
            "ADMIN",
            "SECURITY_ADMIN",
        }
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot revoke this SSH key",
        )

    ssh_key.is_active = False

    db.commit()
    db.refresh(ssh_key)

    return ssh_key

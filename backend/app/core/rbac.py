from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from app.api.auth import get_current_user
from app.db.models import User


ROLES = {
    "ADMIN",
    "SECURITY_ADMIN",
    "DEVELOPER",
    "VIEWER",
}


def require_roles(*allowed_roles: str) -> Callable:
    invalid_roles = set(allowed_roles) - ROLES

    if invalid_roles:
        raise ValueError(
            f"Invalid roles: {', '.join(sorted(invalid_roles))}"
        )

    def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return current_user

    return role_checker

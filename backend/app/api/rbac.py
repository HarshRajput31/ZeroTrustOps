from fastapi import APIRouter, Depends

from app.core.rbac import require_roles

router = APIRouter()


@router.get("/viewer")
def viewer_access(
    current_user=Depends(
        require_roles(
            "ADMIN",
            "SECURITY_ADMIN",
            "DEVELOPER",
            "VIEWER",
        )
    ),
):
    return {
        "message": "Read access granted",
        "username": current_user.username,
        "role": current_user.role,
    }


@router.get("/developer")
def developer_access(
    current_user=Depends(
        require_roles(
            "ADMIN",
            "SECURITY_ADMIN",
            "DEVELOPER",
        )
    ),
):
    return {
        "message": "Developer access granted",
        "username": current_user.username,
        "role": current_user.role,
    }


@router.get("/security-admin")
def security_admin_access(
    current_user=Depends(
        require_roles(
            "ADMIN",
            "SECURITY_ADMIN",
        )
    ),
):
    return {
        "message": "Security admin access granted",
        "username": current_user.username,
        "role": current_user.role,
    }


@router.get("/admin")
def admin_access(
    current_user=Depends(
        require_roles("ADMIN")
    ),
):
    return {
        "message": "Admin access granted",
        "username": current_user.username,
        "role": current_user.role,
    }

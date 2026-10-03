from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.access_requests import router as access_requests_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.jit import router as jit_router
from app.api.rbac import router as rbac_router
from app.api.servers import router as servers_router
from app.api.sessions import router as sessions_router
from app.api.ssh_keys import router as ssh_keys_router
from app.db.dependencies import get_db

app = FastAPI(
    title="ZeroTrustOps API",
    description="Zero-Trust Server Access Platform",
    version="0.10.0",
)

app.include_router(
    auth_router,
    prefix="/auth",
    tags=["Authentication"],
)

app.include_router(
    rbac_router,
    prefix="/rbac",
    tags=["RBAC"],
)

app.include_router(
    servers_router,
    prefix="/servers",
    tags=["Servers"],
)

app.include_router(
    access_requests_router,
    prefix="/access-requests",
    tags=["Access Requests"],
)

app.include_router(
    ssh_keys_router,
    prefix="/ssh-keys",
    tags=["SSH Keys"],
)

app.include_router(
    jit_router,
    prefix="/jit",
    tags=["JIT SSH"],
)

app.include_router(
    audit_router,
    prefix="/audit-logs",
    tags=["Audit Logs"],
)

app.include_router(
    sessions_router,
    prefix="/sessions",
    tags=["Sessions"],
)


@app.get("/")
def root():
    return {
        "project": "ZeroTrustOps",
        "status": "online",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


@app.get("/db-test")
def database_test(db: Session = Depends(get_db)):
    result = db.execute(
        text(
            "SELECT current_database(), current_user"
        )
    ).fetchone()

    return {
        "database": result[0],
        "user": result[1],
        "status": "connected",
    }

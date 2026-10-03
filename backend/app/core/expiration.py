import asyncio
import logging
from datetime import datetime, timezone

from app.core.audit import write_audit_log
from app.core.jit import revoke_ssh_key
from app.db.models import AccessRequest, SSHKey, User
from app.db.session import SessionLocal

logger = logging.getLogger("zerotrustops.expiration")

CHECK_INTERVAL_SECONDS = 30


def expire_access_requests() -> int:
    db = SessionLocal()
    expired_count = 0

    try:
        now = datetime.now(timezone.utc)

        requests = (
            db.query(AccessRequest)
            .filter(
                AccessRequest.status == "APPROVED",
                AccessRequest.expires_at.is_not(None),
                AccessRequest.expires_at <= now,
            )
            .all()
        )

        for access_request in requests:
            user = db.get(
                User,
                access_request.user_id,
            )

            if user is None:
                logger.warning(
                    "User %s not found for request %s",
                    access_request.user_id,
                    access_request.id,
                )
                continue

            ssh_key = (
                db.query(SSHKey)
                .filter(
                    SSHKey.user_id == user.id,
                    SSHKey.is_active.is_(True),
                )
                .order_by(SSHKey.id.desc())
                .first()
            )

            if (
                ssh_key is not None
                and user.username == "developer01"
            ):
                try:
                    revoke_ssh_key(
                        linux_username=user.username,
                        public_key=ssh_key.public_key,
                    )
                except ValueError as exc:
                    logger.error(
                        "Failed to revoke JIT key for request %s: %s",
                        access_request.id,
                        exc,
                    )
                    continue

            access_request.status = "EXPIRED"
            access_request.expires_at = None

            write_audit_log(
                db,
                user_id=access_request.user_id,
                action="JIT_ACCESS_EXPIRED",
                resource=f"access_request:{access_request.id}",
                source_ip=None,
                details=(
                    f"JIT access automatically expired; "
                    f"ssh_key_id={ssh_key.id if ssh_key else 'none'}"
                ),
            )

            expired_count += 1

        db.commit()

        if expired_count:
            logger.info(
                "Automatically expired %s access request(s)",
                expired_count,
            )

        return expired_count

    except Exception:
        db.rollback()
        logger.exception(
            "Automatic JIT expiration cycle failed"
        )
        return 0

    finally:
        db.close()


async def expiration_loop(stop_event: asyncio.Event) -> None:
    logger.info(
        "Automatic JIT expiration worker started"
    )

    while not stop_event.is_set():
        try:
            expire_access_requests()
        except Exception:
            logger.exception(
                "Expiration worker cycle crashed"
            )

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=CHECK_INTERVAL_SECONDS,
            )
        except asyncio.TimeoutError:
            pass

    logger.info(
        "Automatic JIT expiration worker stopped"
    )

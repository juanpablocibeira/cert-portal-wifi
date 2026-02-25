import asyncio
import logging

from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.models import ActivityLog, User

logger = logging.getLogger("cert-portal.node-sync")


async def sync_unregistered_nodes():
    """Fetch unreg nodes from PF, match to local users, and register them."""
    from app.services.packetfence import get_pf_client

    async with async_session() as db:
        pf = await get_pf_client(db)
        nodes = await pf.list_unregistered_nodes()

        for node in nodes:
            mac = node.get("mac", "")
            cn = node.get("last_dot1x_username", "")
            if not cn or not mac:
                continue

            # CN format: "username-certRequestId" — extract username
            parts = cn.rsplit("-", 1)
            if len(parts) != 2:
                continue
            username = parts[0]

            result = await db.execute(
                select(User)
                .where(User.username == username, User.is_active == True)
            )
            user = result.scalar_one_or_none()
            if not user or not user.group or not user.group.pf_category_id:
                continue

            category_id = user.group.pf_category_id
            try:
                await pf.register_node(mac, username, category_id)
                logger.info(
                    f"[NODE-SYNC] Nodo {mac} registrado — user={username}, "
                    f"category_id={category_id}, cn={cn}"
                )
                db.add(ActivityLog(
                    user_id=user.id,
                    action="node_auto_registered",
                    detail=f"MAC={mac}, CN={cn}, category_id={category_id}",
                ))
                await db.commit()
            except Exception as e:
                logger.warning(f"[NODE-SYNC] Error registrando nodo {mac}: {e}")


async def run_node_sync_loop(interval: int | None = None):
    """Infinite loop that runs sync_unregistered_nodes every `interval` seconds."""
    interval = interval or settings.node_sync_interval
    logger.info(f"[NODE-SYNC] Loop iniciado (intervalo={interval}s)")
    while True:
        try:
            await sync_unregistered_nodes()
        except Exception as e:
            logger.warning(f"[NODE-SYNC] Error en ciclo de sync: {e}")
        await asyncio.sleep(interval)

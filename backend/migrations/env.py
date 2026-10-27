import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import get_settings
from app.db.models import Base

target_metadata = Base.metadata


def run_offline():
    context.configure(url=get_settings().database_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def _do(conn):
    context.configure(connection=conn, target_metadata=target_metadata, render_as_batch=conn.dialect.name == "sqlite")
    with context.begin_transaction():
        context.run_migrations()


async def run_online():
    url = context.config.attributes.get("url") or get_settings().database_url
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        await conn.run_sync(_do)
    await engine.dispose()


if context.is_offline_mode():
    run_offline()
else:
    asyncio.run(run_online())

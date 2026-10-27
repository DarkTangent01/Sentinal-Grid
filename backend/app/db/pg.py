from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(url: str | None = None):
    global _engine, _sessionmaker
    url = url or get_settings().database_url
    kwargs = {} if url.startswith("sqlite") else {"pool_size": 10, "max_overflow": 20, "pool_pre_ping": True}
    _engine = create_async_engine(url, **kwargs)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_engine():
    if _engine is None:
        init_engine()
    return _engine


def session_factory() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with session_factory()() as s:
        yield s

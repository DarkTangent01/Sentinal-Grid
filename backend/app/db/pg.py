from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(url: str | None = None, *, pool_size: int | None = None, max_overflow: int | None = None):
    global _engine, _sessionmaker
    st = get_settings()
    url = url or st.database_url
    kwargs = {} if url.startswith("sqlite") else {
        "pool_size": st.db_pool_size if pool_size is None else pool_size,
        "max_overflow": st.db_max_overflow if max_overflow is None else max_overflow,
        "pool_timeout": st.db_pool_timeout_seconds, "pool_recycle": st.db_pool_recycle_seconds, "pool_pre_ping": True}
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

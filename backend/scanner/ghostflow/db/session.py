"""GhostFlow Database Engine & Session Management."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from ..database import get_raw_database_url

_ENGINE: Engine | None = None
_SESSION_FACTORY: sessionmaker[Session] | None = None


def normalize_sqlalchemy_url(raw_url: str | None) -> str:
    """Ensure database URL is formatted correctly for SQLAlchemy 2.0+."""
    if not raw_url:
        return "sqlite:///:memory:"
    # SQLAlchemy requires postgresql:// instead of postgres://
    if raw_url.startswith("postgres://"):
        return "postgresql+psycopg2://" + raw_url[len("postgres://"):]
    if raw_url.startswith("postgresql://") and not raw_url.startswith("postgresql+"):
        return "postgresql+psycopg2://" + raw_url[len("postgresql://"):]
    return raw_url


def get_engine(url: str | None = None, echo: bool = False) -> Engine:
    """Get or create singleton SQLAlchemy Engine."""
    global _ENGINE, _SESSION_FACTORY
    target_url = normalize_sqlalchemy_url(url or get_raw_database_url())

    if _ENGINE is not None:
        return _ENGINE

    if target_url.startswith("postgresql"):
        _ENGINE = create_engine(
            target_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            echo=echo,
        )
    else:
        # SQLite configuration
        connect_args = {"check_same_thread": False} if "sqlite" in target_url else {}
        _ENGINE = create_engine(
            target_url,
            connect_args=connect_args,
            echo=echo,
        )

    _SESSION_FACTORY = sessionmaker(autocommit=False, autoflush=False, bind=_ENGINE)
    return _ENGINE


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Get or create configured sessionmaker factory."""
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None or engine is not None:
        eng = engine or get_engine()
        _SESSION_FACTORY = sessionmaker(autocommit=False, autoflush=False, bind=eng)
    return _SESSION_FACTORY


def reset_engine() -> None:
    """Dispose current engine and reset session factory (used in tests)."""
    global _ENGINE, _SESSION_FACTORY
    if _ENGINE is not None:
        _ENGINE.dispose()
        _ENGINE = None
    _SESSION_FACTORY = None


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for database sessions with automatic commit/rollback."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database session."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()


"""GhostFlow SQLAlchemy Base and Schema Definitions."""

from __future__ import annotations

import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, MetaData, Table, Uuid, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# Shared metadata with standard naming conventions for constraints and indexes
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=convention)


class Base(DeclarativeBase):
    metadata = metadata


# Stub for Supabase Auth users table (auth.users)
# Supabase manages auth.users in the 'auth' schema. Defining it here allows
# SQLAlchemy and Alembic foreign key constraints to resolve cleanly without
# attempting to create or drop auth.users in migrations.
auth_users = Table(
    "users",
    Base.metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    schema="auth",
)


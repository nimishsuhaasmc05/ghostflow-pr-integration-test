"""GhostFlow Authentication Models."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AuthenticatedUser:
    """Represents an independently verified Supabase Auth user identity."""

    id: uuid.UUID
    email: str | None
    role: str = "authenticated"
    claims: dict[str, Any] = field(default_factory=dict)

    @property
    def id_str(self) -> str:
        return str(self.id)

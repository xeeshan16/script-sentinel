"""The authorization audit trail: append-only and hash-chained per site.

Every decision about a script, every policy change and every status change a scan causes
is written as an :class:`AuthorizationEvent`. Events of a site are numbered (``seq``) and
each stores the SHA-256 of the previous event and of its own canonical form, so editing,
deleting or reordering rows afterwards is detectable with :func:`verify_chain`. This is
tamper-*evident*, not tamper-proof: someone with write access to the database can rebuild
the whole chain. Exporting the latest hash elsewhere (day 12's evidence export) closes
that gap.

Appending locks the site row first (``SELECT ... FOR UPDATE`` on PostgreSQL), so two
transactions writing to one site's trail are serialized instead of forking the chain.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from script_sentinel.db.models import AuthorizationEvent, Site, utcnow

GENESIS_HASH = "0" * 64

# Actions written to the trail.
SCRIPT_APPROVED = "script.approved"
SCRIPT_REJECTED = "script.rejected"
SCRIPT_RESET = "script.reset"
STATUS_CHANGED = "script.status_changed"
POLICY_CREATED = "policy.created"
POLICY_REMOVED = "policy.removed"


def _uuid(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


def canonical(event: AuthorizationEvent) -> bytes:
    """The bytes an event's hash covers: every field except its own id and hash."""
    payload = {
        "site_id": _uuid(event.site_id),
        "seq": event.seq,
        "script_id": _uuid(event.script_id),
        "policy_id": _uuid(event.policy_id),
        "locator": event.locator,
        "action": event.action,
        "actor": event.actor,
        "from_status": event.from_status,
        "to_status": event.to_status,
        "reason": event.reason,
        "detail": event.detail,
        "created_at": event.created_at.isoformat(timespec="microseconds"),
        "prev_hash": event.prev_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def event_hash(event: AuthorizationEvent) -> str:
    return hashlib.sha256(canonical(event)).hexdigest()


@dataclass(slots=True)
class AuditLog:
    """Appends events to one site's trail within the caller's transaction."""

    session: AsyncSession
    site_id: uuid.UUID
    clock: Callable[[], datetime] = utcnow
    _seq: int = 0
    _last_hash: str = GENESIS_HASH
    _loaded: bool = False
    written: list[AuthorizationEvent] = field(default_factory=list)

    async def _load(self) -> None:
        # Serialize writers of this site's trail until the transaction ends. SQLite has no
        # row locks (and serializes writers anyway), so the clause is dropped there.
        await self.session.execute(select(Site.id).where(Site.id == self.site_id).with_for_update())
        last = (
            await self.session.execute(
                select(AuthorizationEvent.seq, AuthorizationEvent.hash)
                .where(AuthorizationEvent.site_id == self.site_id)
                .order_by(AuthorizationEvent.seq.desc())
                .limit(1)
            )
        ).one_or_none()
        if last is not None:
            self._seq, self._last_hash = last[0], last[1]
        self._loaded = True

    async def append(
        self,
        action: str,
        *,
        actor: str,
        script_id: uuid.UUID | None = None,
        policy_id: uuid.UUID | None = None,
        locator: str | None = None,
        from_status: str | None = None,
        to_status: str | None = None,
        reason: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuthorizationEvent:
        if not self._loaded:
            await self._load()
        event = AuthorizationEvent(
            id=uuid.uuid4(),
            site_id=self.site_id,
            seq=self._seq + 1,
            script_id=script_id,
            policy_id=policy_id,
            locator=locator,
            action=action,
            actor=actor,
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            detail=detail or {},
            created_at=self.clock(),
            prev_hash=self._last_hash,
        )
        event.hash = event_hash(event)
        self.session.add(event)
        self._seq, self._last_hash = event.seq, event.hash
        self.written.append(event)
        return event


async def list_events(
    session: AsyncSession,
    site_id: uuid.UUID,
    *,
    script_id: uuid.UUID | None = None,
    limit: int = 100,
) -> list[AuthorizationEvent]:
    """A site's events, newest first, optionally for one script."""
    query = select(AuthorizationEvent).where(AuthorizationEvent.site_id == site_id)
    if script_id is not None:
        query = query.where(AuthorizationEvent.script_id == script_id)
    result = await session.scalars(query.order_by(AuthorizationEvent.seq.desc()).limit(limit))
    return list(result)


_VERIFY_PAGE = 1000


@dataclass(frozen=True, slots=True)
class ChainReport:
    ok: bool
    events: int  # events verified (up to the break, if any)
    head_hash: str  # the hash of the last verified event (GENESIS_HASH if none)
    first_bad_seq: int | None = None
    problem: str | None = None


async def verify_chain(session: AsyncSession, site_id: uuid.UUID) -> ChainReport:
    """Recompute a site's chain from the start and report the first break."""
    expected_prev = GENESIS_HASH
    count = 0
    while True:
        # Keyset pages, so a long trail is never loaded at once.
        page = list(
            await session.scalars(
                select(AuthorizationEvent)
                .where(AuthorizationEvent.site_id == site_id, AuthorizationEvent.seq > count)
                .order_by(AuthorizationEvent.seq)
                .limit(_VERIFY_PAGE)
            )
        )
        for event in page:
            count += 1
            if event.seq != count:
                return ChainReport(
                    False, count - 1, expected_prev, event.seq, f"event {count} is missing"
                )
            if event.prev_hash != expected_prev:
                return ChainReport(
                    False,
                    count - 1,
                    expected_prev,
                    event.seq,
                    "prev_hash does not match the previous event (a row was edited or removed)",
                )
            if event_hash(event) != event.hash:
                return ChainReport(
                    False,
                    count - 1,
                    expected_prev,
                    event.seq,
                    "the event's contents do not match its hash",
                )
            expected_prev = event.hash
        if len(page) < _VERIFY_PAGE:
            break
    return ChainReport(True, count, expected_prev)

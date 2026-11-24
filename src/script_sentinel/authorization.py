"""Authorizing scripts (PCI DSS 6.4.3): decisions, policies and the status they produce.

Every script in a site's inventory has a ``status``: ``approved``, ``pending`` or
``rejected``. It is derived, never set directly, from three inputs:

1. **A person's decision** about that script: approve it (with a written justification,
   which 6.4.3 asks for) either *pinned* to the bodies it serves now, or for *any version*
   when the vendor is expected to ship new ones; or reject it.
2. **Policies** that cover many scripts at once:

   * ``origin``: external scripts loaded from one origin;
   * ``prefix``: external scripts whose URL starts with a prefix (a vendor's SDK path);
   * ``hash``: any body, external or inline, with a given SHA-384.

   Origin and prefix policies are either ``expected_to_change`` (any body is fine) or
   ``pinned``, which approves the first body seen (trust on first use) and sends every
   later body back to ``pending``. They can also drop cache-busting query parameters, so
   ``app.js?v=123`` and ``app.js?v=124`` are one script with two versions rather than two
   scripts.
3. **The bodies the script serves right now** (its current versions) and which of them
   were approved.

The rules, in order:

* a rejection always wins;
* an approval for any version approves;
* a pinned approval approves while every current body was approved (or matches a hash
  policy), and otherwise the script is ``pending`` again: its code changed since a person
  looked at it. A per-script pin is deliberate, so a broader origin or prefix policy does
  not override it;
* without a decision, a hash policy approves bodies it lists, then the most specific
  origin or prefix policy applies;
* anything else is ``pending``.

Statuses are recomputed after every scan, decision and policy change. Each status change
is written to the audit trail (see :mod:`script_sentinel.audit`), so the trail is the
complete history of every script's authorization.
"""

from __future__ import annotations

import base64
import binascii
import re
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from script_sentinel import audit
from script_sentinel.db.models import (
    ApprovalScope,
    AuthorizationStatus,
    ChangePolicy,
    Decision,
    Policy,
    PolicyKind,
    Script,
    ScriptKind,
    ScriptVersion,
    Site,
    utcnow,
)
from script_sentinel.origins import (
    InvalidUrlError,
    normalize_url_prefix,
    origin_of,
    parse_origin,
)
from script_sentinel.sites import ConflictError, NotFoundError, ValidationError, get_site

MAX_ACTOR_LENGTH = 128
MAX_JUSTIFICATION_LENGTH = 2000
MAX_IGNORED_PARAMS = 20
_PARAM_NAME = re.compile(r"^[^\s&=#]{1,64}$")
_HEX384 = re.compile(r"^[0-9a-f]{96}$")


# --- validation -------------------------------------------------------------------------


def validate_actor(actor: str) -> str:
    """Who made a change. Free text until the API has authentication (day 13)."""
    value = (actor or "").strip()
    if not value:
        raise ValidationError("an actor (who is making this change) is required")
    if len(value) > MAX_ACTOR_LENGTH:
        raise ValidationError(f"actor is longer than {MAX_ACTOR_LENGTH} characters")
    if any(ord(ch) < 0x20 for ch in value):
        raise ValidationError("actor contains control characters")
    return value


def validate_justification(text: str, what: str = "a justification") -> str:
    value = (text or "").strip()
    if not value:
        raise ValidationError(f"{what} is required (PCI DSS 6.4.3 asks for one in writing)")
    if len(value) > MAX_JUSTIFICATION_LENGTH:
        raise ValidationError(f"{what} is longer than {MAX_JUSTIFICATION_LENGTH} characters")
    return value


def parse_sha384(value: str) -> str:
    """A hex SHA-384 from hex or from an SRI value (``sha384-<base64>``)."""
    raw = (value or "").strip()
    if raw.lower().startswith("sha384-"):
        try:
            digest = base64.b64decode(raw[7:], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValidationError(f"{value!r} is not a valid sha384- integrity value") from exc
        if len(digest) != 48:
            raise ValidationError(f"{value!r} is not a SHA-384 digest (48 bytes)")
        return digest.hex()
    lowered = raw.lower()
    if not _HEX384.fullmatch(lowered):
        raise ValidationError(
            "a hash policy takes a SHA-384 as 96 hex characters or as sha384-<base64>"
        )
    return lowered


def normalize_ignore_query(names: Iterable[str]) -> list[str]:
    cleaned = sorted({n.strip() for n in names if n.strip()})
    if "*" in cleaned and len(cleaned) > 1:
        raise ValidationError("ignore_query '*' drops the whole query; list it alone")
    if len(cleaned) > MAX_IGNORED_PARAMS:
        raise ValidationError(f"at most {MAX_IGNORED_PARAMS} ignored query parameters")
    for name in cleaned:
        if not _PARAM_NAME.fullmatch(name):
            raise ValidationError(f"{name!r} is not a query parameter name")
    return cleaned


def normalize_policy_match(kind: PolicyKind, value: str) -> str:
    try:
        if kind is PolicyKind.ORIGIN:
            return str(parse_origin(value))
        if kind is PolicyKind.PREFIX:
            return normalize_url_prefix(value)
    except InvalidUrlError as exc:
        raise ValidationError(str(exc)) from exc
    return parse_sha384(value)


# --- matching and locators --------------------------------------------------------------


def _url_matches(policy: Policy, url: str) -> bool:
    """Whether an origin or prefix policy matches ``url``."""
    if policy.kind is PolicyKind.PREFIX:
        return url.startswith(policy.match)
    try:
        return str(origin_of(url)) == policy.match
    except InvalidUrlError:
        return False


def url_policy_for(url: str, policies: Sequence[Policy]) -> Policy | None:
    """The origin or prefix policy that governs ``url``: the longest matching prefix, else
    the origin. Ties (impossible for distinct prefixes) fall back to creation order."""
    best: Policy | None = None
    for policy in policies:
        if policy.kind is PolicyKind.HASH or not _url_matches(policy, url):
            continue
        if best is None or _specificity(policy) > _specificity(best):
            best = policy
    return best


def _specificity(policy: Policy) -> tuple[int, int]:
    return (1, len(policy.match)) if policy.kind is PolicyKind.PREFIX else (0, 0)


def strip_query(url: str, ignore: Sequence[str]) -> str:
    """``url`` without the listed query parameters (``*``: without any query).

    The remaining parameters keep their order and exact encoding, so nothing but the
    ignored ones changes.
    """
    if not ignore:
        return url
    parts = urlsplit(url)
    if not parts.query:
        return url
    if "*" in ignore:
        kept: list[str] = []
    else:
        drop = set(ignore)
        kept = [
            pair
            for pair in parts.query.split("&")
            if pair and unquote(pair.split("=", 1)[0].replace("+", " ")) not in drop
        ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(kept), parts.fragment))


def external_locator(src: str, policies: Sequence[Policy]) -> str:
    """The inventory locator of an external script, after its policy's query rules."""
    policy = url_policy_for(src, policies)
    return strip_query(src, policy.ignore_query) if policy is not None else src


# --- evaluation -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VersionState:
    id: uuid.UUID
    sha384: str
    approved: bool


@dataclass(frozen=True, slots=True)
class Verdict:
    status: AuthorizationStatus
    reason: str
    policy_id: uuid.UUID | None = None
    # Versions a pinning policy approves now (trust on first use).
    approve: tuple[uuid.UUID, ...] = ()


def describe_policy(policy: Policy) -> str:
    if policy.kind is PolicyKind.HASH:
        return f"hash policy sha384:{policy.match[:16]}…"
    return f"{policy.kind.value} policy {policy.match}"


def evaluate(
    script: Script,
    current: Sequence[VersionState],
    *,
    has_approved_versions: bool,
    policies: Sequence[Policy],
) -> Verdict:
    """The status ``script`` should have. Pure: reads its arguments, changes nothing."""
    by_hash = {p.match: p for p in policies if p.kind is PolicyKind.HASH}
    hash_cover = {v.id: by_hash[v.sha384] for v in current if v.sha384 in by_hash}
    uncovered = [v for v in current if not v.approved and v.id not in hash_cover]

    if script.decision is Decision.REJECTED:
        return Verdict(AuthorizationStatus.REJECTED, f"rejected by {script.decided_by}")
    if script.decision is Decision.APPROVED:
        if script.approval_scope is ApprovalScope.ANY_VERSION:
            return Verdict(
                AuthorizationStatus.APPROVED, f"approved by {script.decided_by} for any version"
            )
        if current and not uncovered:
            via_hash = next((hash_cover[v.id] for v in current if not v.approved), None)
            if via_hash is not None:
                return Verdict(
                    AuthorizationStatus.APPROVED,
                    f"approved by {script.decided_by}; a newer body matches "
                    f"{describe_policy(via_hash)}",
                    via_hash.id,
                )
            return Verdict(AuthorizationStatus.APPROVED, f"approved by {script.decided_by}")
        return Verdict(
            AuthorizationStatus.PENDING,
            f"the body changed since {script.decided_by} approved it (pinned)",
        )

    if current and len(hash_cover) == len(current):
        policy = hash_cover[current[0].id]
        return Verdict(
            AuthorizationStatus.APPROVED, f"approved by {describe_policy(policy)}", policy.id
        )

    url_policy = (
        url_policy_for(script.locator, policies) if script.kind is ScriptKind.EXTERNAL else None
    )
    if url_policy is not None:
        label = describe_policy(url_policy)
        if url_policy.change is ChangePolicy.EXPECTED_TO_CHANGE:
            return Verdict(
                AuthorizationStatus.APPROVED,
                f"approved by {label} (expected to change)",
                url_policy.id,
            )
        if not current:
            return Verdict(
                AuthorizationStatus.PENDING,
                f"{label} pins the first body, and none has been fetched yet",
                url_policy.id,
            )
        if not has_approved_versions:
            return Verdict(
                AuthorizationStatus.APPROVED,
                f"approved by {label}, pinned to the first body seen",
                url_policy.id,
                tuple(v.id for v in current if not v.approved),
            )
        if not uncovered:
            return Verdict(
                AuthorizationStatus.APPROVED, f"approved by {label} (pinned)", url_policy.id
            )
        return Verdict(
            AuthorizationStatus.PENDING,
            f"the body changed since {label} pinned it",
            url_policy.id,
        )
    return Verdict(AuthorizationStatus.PENDING, "no decision or policy covers this script yet")


# --- applying verdicts ------------------------------------------------------------------


@dataclass(slots=True)
class _ScriptVersions:
    by_id: dict[uuid.UUID, ScriptVersion] = field(default_factory=dict)
    _approved_scripts: set[uuid.UUID] | None = None

    def current(self, script: Script) -> list[ScriptVersion]:
        return [
            self.by_id[vid]
            for vid in (uuid.UUID(v) for v in script.current_version_ids)
            if vid in self.by_id
        ]

    def any_approved(self, script: Script) -> bool:
        if self._approved_scripts is None:
            self._approved_scripts = {
                v.script_id for v in self.by_id.values() if v.approved_at is not None
            }
        return script.id in self._approved_scripts

    def mark_approved(self, version: ScriptVersion) -> None:
        if self._approved_scripts is not None:
            self._approved_scripts.add(version.script_id)


async def _load_versions(session: AsyncSession, scripts: Sequence[Script]) -> _ScriptVersions:
    loaded = _ScriptVersions()
    ids = [s.id for s in scripts]
    for start in range(0, len(ids), 500):
        result = await session.scalars(
            select(ScriptVersion)
            .options(
                load_only(
                    ScriptVersion.id,
                    ScriptVersion.script_id,
                    ScriptVersion.sha384,
                    ScriptVersion.approved_at,
                    ScriptVersion.approved_by,
                )
            )
            .where(ScriptVersion.script_id.in_(ids[start : start + 500]))
        )
        for version in result:
            loaded.by_id[version.id] = version
    return loaded


def _states(versions: Sequence[ScriptVersion]) -> list[VersionState]:
    return [VersionState(v.id, v.sha384, v.approved_at is not None) for v in versions]


async def load_policies(session: AsyncSession, site_id: uuid.UUID) -> list[Policy]:
    result = await session.scalars(
        select(Policy).where(Policy.site_id == site_id).order_by(Policy.created_at, Policy.id)
    )
    return list(result)


@dataclass(frozen=True, slots=True)
class Change:
    script: Script
    from_status: AuthorizationStatus | None
    to_status: AuthorizationStatus


async def reevaluate(
    session: AsyncSession,
    site: Site,
    scripts: Sequence[Script],
    log: audit.AuditLog,
    *,
    actor: str,
    policies: Sequence[Policy] | None = None,
    detail: dict[str, Any] | None = None,
    clock: Callable[[], datetime] = utcnow,
) -> list[Change]:
    """Recompute the status of ``scripts`` and record every change in the audit trail.

    A script that has never been evaluated (just discovered) always gets an event, so the
    trail shows when each script entered the inventory and with which status.
    """
    if not scripts:
        return []
    if policies is None:
        policies = await load_policies(session, site.id)
    versions = await _load_versions(session, scripts)
    changes: list[Change] = []
    now = clock()
    for script in scripts:
        current = versions.current(script)
        verdict = evaluate(
            script,
            _states(current),
            has_approved_versions=versions.any_approved(script),
            policies=policies,
        )
        approved_now = [versions.by_id[vid] for vid in verdict.approve]
        for version in approved_now:
            version.approved_at = now
            version.approved_by = f"policy:{verdict.policy_id}"
            versions.mark_approved(version)
        first = script.status_changed_at is None
        moved = (
            first or verdict.status is not script.status or verdict.policy_id != (script.policy_id)
        )
        previous = None if first else script.status
        script.status_reason = verdict.reason[:512]
        if not moved:
            continue
        script.status = verdict.status
        script.policy_id = verdict.policy_id
        script.status_changed_at = now
        event_detail: dict[str, Any] = {
            **(detail or {}),
            "current_sha384": [v.sha384 for v in current],
        }
        if approved_now:
            event_detail["approved_sha384"] = [v.sha384 for v in approved_now]
        await log.append(
            audit.STATUS_CHANGED,
            actor=actor,
            script_id=script.id,
            policy_id=verdict.policy_id,
            locator=script.locator,
            from_status=previous.value if previous else None,
            to_status=verdict.status.value,
            reason=verdict.reason,
            detail=event_detail,
        )
        changes.append(Change(script, previous, verdict.status))
    await session.flush()
    return changes


# --- decisions --------------------------------------------------------------------------


async def _site_script(
    session: AsyncSession, site_name: str, script_id: uuid.UUID
) -> tuple[Site, Script]:
    site = await get_site(session, site_name)
    script = await session.scalar(
        select(Script).where(Script.site_id == site.id, Script.id == script_id)
    )
    if script is None:
        raise NotFoundError(f"script {script_id} not found in site {site_name!r}")
    return site, script


async def _decide(
    session: AsyncSession,
    site: Site,
    script: Script,
    *,
    action: str,
    actor: str,
    reason: str,
    approve_current: bool,
    clock: Callable[[], datetime],
) -> Script:
    log = audit.AuditLog(session, site.id, clock=clock)
    policies = await load_policies(session, site.id)
    versions = await _load_versions(session, [script])
    current = versions.current(script)
    now = clock()
    approved_now: list[ScriptVersion] = []
    if approve_current:
        for version in current:
            if version.approved_at is None:
                version.approved_at = now
                version.approved_by = actor
                versions.mark_approved(version)
                approved_now.append(version)
    verdict = evaluate(
        script,
        _states(current),
        has_approved_versions=versions.any_approved(script),
        policies=policies,
    )
    previous = script.status if script.status_changed_at is not None else None
    script.status = verdict.status
    script.status_reason = verdict.reason[:512]
    script.policy_id = verdict.policy_id
    script.status_changed_at = now
    detail: dict[str, Any] = {"current_sha384": [v.sha384 for v in current]}
    if script.approval_scope is not None:
        detail["scope"] = script.approval_scope.value
    if approved_now:
        detail["approved_sha384"] = [v.sha384 for v in approved_now]
    await log.append(
        action,
        actor=actor,
        script_id=script.id,
        policy_id=verdict.policy_id,
        locator=script.locator,
        from_status=previous.value if previous else None,
        to_status=verdict.status.value,
        reason=reason,
        detail=detail,
    )
    await session.flush()
    return script


async def approve_script(
    session: AsyncSession,
    site_name: str,
    script_id: uuid.UUID,
    *,
    actor: str,
    justification: str,
    scope: ApprovalScope = ApprovalScope.PINNED,
    clock: Callable[[], datetime] = utcnow,
) -> Script:
    """Approve a script with a written justification.

    ``pinned`` approves the bodies it serves now; a later body makes it ``pending`` again
    until someone approves that one too (approving again does). ``any_version`` approves
    whatever the vendor serves. A pinned approval needs a body to pin.
    """
    actor = validate_actor(actor)
    justification = validate_justification(justification)
    site, script = await _site_script(session, site_name, script_id)
    if scope is ApprovalScope.PINNED and not script.current_version_ids:
        raise ValidationError(
            "this script has no fetched body to pin yet; scan again, or approve it for any "
            "version if the vendor is expected to change it"
        )
    now = clock()
    script.decision = Decision.APPROVED
    script.approval_scope = scope
    script.justification = justification
    script.decided_by = actor
    script.decided_at = now
    return await _decide(
        session,
        site,
        script,
        action=audit.SCRIPT_APPROVED,
        actor=actor,
        reason=justification,
        approve_current=scope is ApprovalScope.PINNED,
        clock=clock,
    )


async def reject_script(
    session: AsyncSession,
    site_name: str,
    script_id: uuid.UUID,
    *,
    actor: str,
    reason: str,
    clock: Callable[[], datetime] = utcnow,
) -> Script:
    """Reject a script: it must not run on the site. Rejection beats every policy."""
    actor = validate_actor(actor)
    reason = validate_justification(reason, "a reason")
    site, script = await _site_script(session, site_name, script_id)
    script.decision = Decision.REJECTED
    script.approval_scope = None
    script.justification = reason
    script.decided_by = actor
    script.decided_at = clock()
    return await _decide(
        session,
        site,
        script,
        action=audit.SCRIPT_REJECTED,
        actor=actor,
        reason=reason,
        approve_current=False,
        clock=clock,
    )


async def reset_script(
    session: AsyncSession,
    site_name: str,
    script_id: uuid.UUID,
    *,
    actor: str,
    reason: str,
    clock: Callable[[], datetime] = utcnow,
) -> Script:
    """Withdraw the decision about a script; policies alone decide its status again.

    Earlier approvals of individual bodies stay on record (they are history).
    """
    actor = validate_actor(actor)
    reason = validate_justification(reason, "a reason")
    site, script = await _site_script(session, site_name, script_id)
    if script.decision is None:
        raise ConflictError("there is no decision about this script to withdraw")
    script.decision = None
    script.approval_scope = None
    script.justification = None
    script.decided_by = None
    script.decided_at = None
    return await _decide(
        session,
        site,
        script,
        action=audit.SCRIPT_RESET,
        actor=actor,
        reason=reason,
        approve_current=False,
        clock=clock,
    )


# --- policies ---------------------------------------------------------------------------


def _policy_detail(policy: Policy) -> dict[str, Any]:
    return {
        "kind": policy.kind.value,
        "match": policy.match,
        "change": policy.change.value,
        "ignore_query": list(policy.ignore_query),
        "justification": policy.justification,
    }


async def _site_scripts(session: AsyncSession, site: Site) -> list[Script]:
    result = await session.scalars(
        select(Script).where(Script.site_id == site.id).order_by(Script.kind, Script.locator)
    )
    return list(result)


async def create_policy(
    session: AsyncSession,
    site_name: str,
    *,
    kind: PolicyKind,
    match: str,
    actor: str,
    justification: str,
    change: ChangePolicy = ChangePolicy.PINNED,
    ignore_query: Sequence[str] = (),
    clock: Callable[[], datetime] = utcnow,
) -> tuple[Policy, list[Change]]:
    """Add a policy and re-evaluate the site's inventory under it.

    A query rule (``ignore_query``) applies to scripts found from the next scan on;
    existing inventory entries keep the locators they were recorded under.
    """
    actor = validate_actor(actor)
    justification = validate_justification(justification)
    site = await get_site(session, site_name)
    normalized = normalize_policy_match(kind, match)
    ignored = normalize_ignore_query(ignore_query)
    if kind is PolicyKind.HASH:
        if change is not ChangePolicy.PINNED:
            raise ValidationError("a hash policy approves one exact body; it cannot change")
        if ignored:
            raise ValidationError("ignore_query applies to origin and prefix policies only")
    duplicate = await session.scalar(
        select(Policy.id).where(
            Policy.site_id == site.id, Policy.kind == kind, Policy.match == normalized
        )
    )
    if duplicate is not None:
        raise ConflictError(
            f"site {site_name!r} already has a {kind.value} policy for {normalized}"
        )
    policy = Policy(
        id=uuid.uuid4(),
        site_id=site.id,
        kind=kind,
        match=normalized,
        change=change,
        ignore_query=ignored,
        justification=justification,
        created_by=actor,
        created_at=clock(),
    )
    session.add(policy)
    await session.flush()
    log = audit.AuditLog(session, site.id, clock=clock)
    await log.append(
        audit.POLICY_CREATED,
        actor=actor,
        policy_id=policy.id,
        reason=justification,
        detail=_policy_detail(policy),
    )
    changes = await reevaluate(
        session,
        site,
        await _site_scripts(session, site),
        log,
        actor=actor,
        detail={"cause": audit.POLICY_CREATED, "policy_id": str(policy.id)},
        clock=clock,
    )
    return policy, changes


async def list_policies(session: AsyncSession, site_name: str) -> list[Policy]:
    site = await get_site(session, site_name)
    return await load_policies(session, site.id)


async def remove_policy(
    session: AsyncSession,
    site_name: str,
    policy_id: uuid.UUID,
    *,
    actor: str,
    reason: str,
    clock: Callable[[], datetime] = utcnow,
) -> list[Change]:
    """Remove a policy and re-evaluate the scripts it covered."""
    actor = validate_actor(actor)
    reason = validate_justification(reason, "a reason")
    site = await get_site(session, site_name)
    policies = await load_policies(session, site.id)
    policy = next((p for p in policies if p.id == policy_id), None)
    if policy is None:
        raise NotFoundError(f"policy {policy_id} not found in site {site_name!r}")
    log = audit.AuditLog(session, site.id, clock=clock)
    await log.append(
        audit.POLICY_REMOVED,
        actor=actor,
        policy_id=policy.id,
        reason=reason,
        detail=_policy_detail(policy),
    )
    # Re-evaluate while the policy row still exists, so scripts.policy_id moves off it
    # here rather than being nulled behind the session's back by ON DELETE SET NULL.
    changes = await reevaluate(
        session,
        site,
        await _site_scripts(session, site),
        log,
        actor=actor,
        policies=[p for p in policies if p.id != policy.id],
        detail={"cause": audit.POLICY_REMOVED, "policy_id": str(policy.id)},
        clock=clock,
    )
    await session.delete(policy)
    await session.flush()
    return changes

"""Script bodies: hashing them and keeping a version history per script.

Every body a script serves becomes a :class:`ScriptVersion`, identified within its script
by the SHA-384 of the exact bytes. Seeing the same body again only moves its
``last_seen_at``; a body never seen before is a new version, and a new version of a script
that already had one is a *change*. Changes are what the policy engine and the findings
(:mod:`script_sentinel.findings`) look at; :func:`diff_versions` compares any two versions.
"""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from script_sentinel.changes import ChangeAnalysis, analyze_change
from script_sentinel.db.models import Script, ScriptVersion
from script_sentinel.jstokens import normalized_sha384
from script_sentinel.sites import NotFoundError, ValidationError, get_site
from script_sentinel.sri import body_digests


@dataclass(frozen=True, slots=True)
class BodyDigest:
    """What is kept about one script body."""

    sha384: str  # hex, over the exact bytes
    normalized_sha384: str  # hex, over jstokens.normalize(text)
    size_bytes: int
    text: str  # the decoded body as stored (NUL characters replaced, see decode_script)
    # Base64 digests for sha256/384/512, to check integrity attributes that use any of them.
    digests: dict[str, str]

    @property
    def sri(self) -> str:
        """``sha384-<base64>``: an integrity value, or a CSP hash source for inline code."""
        return "sha384-" + self.digests["sha384"]


def _charset(content_type: str | None) -> str | None:
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.partition("=")
        if key.strip().lower() == "charset":
            return value.strip().strip("\"'") or None
    return None


def decode_script(body: bytes, content_type: str | None = None) -> str:
    """Decode a script the way browsers do: BOM, then the header charset, then UTF-8.

    NUL characters become U+FFFD, because PostgreSQL text can't hold them. The hashes are
    computed over the raw bytes, so this never hides a change.
    """
    text: str | None = None
    for bom, encoding in (
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if body.startswith(bom):
            text = body[len(bom) :].decode(encoding, errors="replace")
            break
    if text is None:
        charset = _charset(content_type)
        if charset:
            try:
                text = body.decode(charset, errors="replace")
            except LookupError:
                text = None
    if text is None:
        text = body.decode("utf-8", errors="replace")
    return text.replace("\x00", "�")


def digest_body(body: bytes, content_type: str | None = None) -> BodyDigest:
    """Hash a body. CPU-bound for large scripts; scans run it in a worker thread."""
    text = decode_script(body, content_type)
    return BodyDigest(
        sha384=hashlib.sha384(body).hexdigest(),
        normalized_sha384=normalized_sha384(text),
        size_bytes=len(body),
        text=text,
        digests=body_digests(body),
    )


@dataclass(frozen=True, slots=True)
class Recorded:
    version: ScriptVersion
    new_version: bool  # this body had never been seen for this script
    changed: bool  # ...and the script already had a different body before


@dataclass(slots=True)
class VersionRecorder:
    """Upserts the versions seen during one scan of one site."""

    _known: dict[tuple[uuid.UUID, str], ScriptVersion] = field(default_factory=dict)
    _scripts_with_versions: set[uuid.UUID] = field(default_factory=set)

    @classmethod
    async def load(
        cls, session: AsyncSession, site_id: uuid.UUID, sha384s: Iterable[str]
    ) -> VersionRecorder:
        """Load the existing versions this scan may see again (without their bodies)."""
        recorder = cls()
        wanted = sorted(set(sha384s))
        site_scripts = select(Script.id).where(Script.site_id == site_id)
        recorder._scripts_with_versions = set(
            await session.scalars(
                select(ScriptVersion.script_id)
                .where(ScriptVersion.script_id.in_(site_scripts))
                .distinct()
            )
        )
        # Chunked to stay well under bind-parameter limits.
        for start in range(0, len(wanted), 500):
            chunk = wanted[start : start + 500]
            for version in await session.scalars(
                select(ScriptVersion)
                .options(
                    load_only(
                        ScriptVersion.id,
                        ScriptVersion.script_id,
                        ScriptVersion.sha384,
                        ScriptVersion.first_seen_at,
                        ScriptVersion.last_seen_at,
                    )
                )
                .where(ScriptVersion.script_id.in_(site_scripts), ScriptVersion.sha384.in_(chunk))
            ):
                recorder._known[(version.script_id, version.sha384)] = version
        return recorder

    def record(
        self, session: AsyncSession, script: Script, digest: BodyDigest, seen_at: datetime
    ) -> Recorded:
        """The version of ``script`` with this body, created if it is new.

        ``script.id`` must be set (new scripts get their id before they are flushed).
        """
        key = (script.id, digest.sha384)
        version = self._known.get(key)
        if version is not None:
            version.last_seen_at = max(version.last_seen_at, seen_at)
            return Recorded(version, new_version=False, changed=False)
        changed = script.id in self._scripts_with_versions
        version = ScriptVersion(
            id=uuid.uuid4(),
            script_id=script.id,
            sha384=digest.sha384,
            normalized_sha384=digest.normalized_sha384,
            size_bytes=digest.size_bytes,
            content=digest.text,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
        )
        session.add(version)
        self._known[key] = version
        self._scripts_with_versions.add(script.id)
        return Recorded(version, new_version=True, changed=changed)


_SUMMARY_COLUMNS = (
    ScriptVersion.id,
    ScriptVersion.script_id,
    ScriptVersion.sha384,
    ScriptVersion.normalized_sha384,
    ScriptVersion.size_bytes,
    ScriptVersion.first_seen_at,
    ScriptVersion.last_seen_at,
    ScriptVersion.approved_at,
    ScriptVersion.approved_by,
)


async def versions_by_script(
    session: AsyncSession, script_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, list[ScriptVersion]]:
    """Each script's versions without their bodies, most recently seen first."""
    ids = list(script_ids)
    grouped: dict[uuid.UUID, list[ScriptVersion]] = {i: [] for i in ids}
    for start in range(0, len(ids), 500):
        result = await session.scalars(
            select(ScriptVersion)
            .options(load_only(*_SUMMARY_COLUMNS))
            .where(ScriptVersion.script_id.in_(ids[start : start + 500]))
            .order_by(ScriptVersion.last_seen_at.desc(), ScriptVersion.first_seen_at.desc())
        )
        for version in result:
            grouped[version.script_id].append(version)
    return grouped


async def get_script(session: AsyncSession, site_name: str, script_id: uuid.UUID) -> Script:
    site = await get_site(session, site_name)
    script = await session.scalar(
        select(Script).where(Script.site_id == site.id, Script.id == script_id)
    )
    if script is None:
        raise NotFoundError(f"script {script_id} not found in site {site_name!r}")
    return script


async def find_script(session: AsyncSession, site_name: str, locator: str) -> Script:
    """A script by its locator (its src URL, or ``<page URL>#inline-<n>``)."""
    site = await get_site(session, site_name)
    script = await session.scalar(
        select(Script).where(Script.site_id == site.id, Script.locator == locator)
    )
    if script is None:
        raise NotFoundError(
            f"no script {locator!r} in site {site_name!r}; list them with: "
            f"sentinel scripts list {site_name}"
        )
    return script


async def get_version(
    session: AsyncSession, site_name: str, script_id: uuid.UUID, version_id: uuid.UUID
) -> ScriptVersion:
    """One version of a script, with its body."""
    script = await get_script(session, site_name, script_id)
    version = await session.scalar(
        select(ScriptVersion).where(
            ScriptVersion.script_id == script.id, ScriptVersion.id == version_id
        )
    )
    if version is None:
        raise NotFoundError(f"version {version_id} of script {script_id} not found")
    return version


async def resolve_version(session: AsyncSession, script: Script, ref: str) -> ScriptVersion:
    """A version of ``script`` (without its body) by id, by a prefix of its hex SHA-384, or
    by a prefix of its SRI value (``sha384-…``, as ``sentinel scripts show`` prints it).

    Prefixes need at least 8 characters after any ``sha384-``.
    """
    ref = ref.strip()
    versions = (await versions_by_script(session, [script.id]))[script.id]
    try:
        wanted = uuid.UUID(ref)
    except ValueError:
        wanted = None
    if wanted is not None:
        matches = [v for v in versions if v.id == wanted]
    elif ref.startswith("sha384-") and len(ref) >= 15:
        matches = [v for v in versions if v.sri.startswith(ref)]
    elif len(ref) >= 8 and all(c in "0123456789abcdef" for c in ref.lower()):
        matches = [v for v in versions if v.sha384.startswith(ref.lower())]
    else:
        raise ValidationError(
            f"{ref!r} is not a version id, a SHA-384 prefix (8+ hex) or an SRI prefix "
            "(sha384- and 8+ characters)"
        )
    if not matches:
        raise NotFoundError(f"no version {ref!r} of script {script.locator!r}")
    if len(matches) > 1:
        raise ValidationError(f"{ref!r} matches {len(matches)} versions; give more characters")
    return matches[0]


@dataclass(frozen=True, slots=True)
class VersionDiff:
    script: Script
    old: ScriptVersion
    new: ScriptVersion
    analysis: ChangeAnalysis


async def diff_versions(
    session: AsyncSession,
    site_name: str,
    script_id: uuid.UUID,
    *,
    from_ref: str | None = None,
    to_ref: str | None = None,
) -> VersionDiff:
    """Compare two versions of a script (see :func:`resolve_version` for ``*_ref``).

    By default ``to`` is the body seen most recently and ``from`` the one seen before it.
    """
    script = await get_script(session, site_name, script_id)
    history = (await versions_by_script(session, [script.id]))[script.id]
    if to_ref is not None:
        new = await resolve_version(session, script, to_ref)
    elif history:
        new = history[0]
    else:
        raise ValidationError(f"script {script.locator!r} has no versions yet")
    if from_ref is not None:
        old = await resolve_version(session, script, from_ref)
    else:
        older = [v for v in history if v.id != new.id]
        if not older:
            raise ValidationError(f"script {script.locator!r} has only one version")
        old = older[0]
    rows = await session.execute(
        select(ScriptVersion.id, ScriptVersion.content).where(
            ScriptVersion.id.in_([old.id, new.id])
        )
    )
    texts = {row[0]: row[1] for row in rows}
    analysis = await asyncio.to_thread(
        analyze_change,
        texts.get(old.id) or "",
        texts.get(new.id) or "",
        old_size=old.size_bytes,
        new_size=new.size_bytes,
    )
    return VersionDiff(script, old, new, analysis)

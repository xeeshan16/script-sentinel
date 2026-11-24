"""The authorization rules without a database: parsing, matching, locators, evaluation."""

from __future__ import annotations

import base64
import hashlib
import uuid

import pytest

from script_sentinel.authorization import (
    VersionState,
    describe_policy,
    evaluate,
    external_locator,
    normalize_ignore_query,
    normalize_policy_match,
    parse_sha384,
    strip_query,
    url_policy_for,
    validate_actor,
    validate_justification,
)
from script_sentinel.db.models import (
    ApprovalScope,
    AuthorizationStatus,
    ChangePolicy,
    Decision,
    Policy,
    PolicyKind,
    Script,
    ScriptKind,
)
from script_sentinel.origins import InvalidUrlError, normalize_url_prefix
from script_sentinel.sites import ValidationError

SHA_A = hashlib.sha384(b"a").hexdigest()
SHA_B = hashlib.sha384(b"b").hexdigest()
CDN = "https://cdn.vendor.example"


def _policy(
    kind: PolicyKind,
    match: str,
    change: ChangePolicy = ChangePolicy.PINNED,
    ignore_query: list[str] | None = None,
) -> Policy:
    return Policy(
        id=uuid.uuid4(),
        kind=kind,
        match=match,
        change=change,
        ignore_query=ignore_query or [],
        justification="test",
        created_by="tester",
    )


def _script(
    locator: str = f"{CDN}/sdk/v1/widget.js",
    kind: ScriptKind = ScriptKind.EXTERNAL,
    decision: Decision | None = None,
    scope: ApprovalScope | None = None,
) -> Script:
    return Script(
        id=uuid.uuid4(),
        kind=kind,
        locator=locator,
        decision=decision,
        approval_scope=scope,
        decided_by="alice" if decision else None,
    )


def _v(sha: str, approved: bool = False) -> VersionState:
    return VersionState(uuid.uuid4(), sha, approved)


# --- validation -------------------------------------------------------------------------


def test_actor_and_justification_are_required_and_bounded() -> None:
    assert validate_actor("  alice ") == "alice"
    for bad in ("", "   ", "a" * 129, "bob\nadmin"):
        with pytest.raises(ValidationError):
            validate_actor(bad)
    assert validate_justification(" needed for checkout ") == "needed for checkout"
    with pytest.raises(ValidationError, match=r"6\.4\.3"):
        validate_justification("  ")
    with pytest.raises(ValidationError, match="a reason is longer"):
        validate_justification("x" * 2001, "a reason")


def test_parse_sha384_accepts_hex_and_sri_values() -> None:
    digest = hashlib.sha384(b"a").digest()
    sri = "sha384-" + base64.b64encode(digest).decode()
    assert parse_sha384(sri) == SHA_A
    assert parse_sha384("SHA384-" + sri[7:]) == SHA_A
    assert parse_sha384(SHA_A.upper()) == SHA_A
    for bad in (
        "sha384-!!!",
        "sha384-" + base64.b64encode(b"short").decode(),
        "sha256-" + base64.b64encode(hashlib.sha256(b"a").digest()).decode(),
        SHA_A[:-1],
        "",
    ):
        with pytest.raises(ValidationError):
            parse_sha384(bad)


def test_policy_matches_are_normalized() -> None:
    assert normalize_policy_match(PolicyKind.ORIGIN, "HTTPS://CDN.Vendor.example:443/") == CDN
    assert (
        normalize_policy_match(PolicyKind.PREFIX, "https://CDN.vendor.example/sdk/")
        == f"{CDN}/sdk/"
    )
    assert normalize_policy_match(PolicyKind.HASH, SHA_A) == SHA_A
    with pytest.raises(ValidationError, match="bare origin"):
        normalize_policy_match(PolicyKind.ORIGIN, f"{CDN}/sdk")
    with pytest.raises(ValidationError, match="query or fragment"):
        normalize_policy_match(PolicyKind.PREFIX, f"{CDN}/sdk?v=1")


def test_url_prefixes_always_have_a_path() -> None:
    # Without the slash, "https://cdn.vendor.example" would also match
    # "https://cdn.vendor.example.evil.test/...".
    assert normalize_url_prefix("https://cdn.vendor.example") == f"{CDN}/"
    assert normalize_url_prefix("http://h.example:8080/a/B") == "http://h.example:8080/a/B"
    for bad in ("https://h.example/a#x", "https://h.example/a?", "ftp://h.example/", "x"):
        with pytest.raises(InvalidUrlError):
            normalize_url_prefix(bad)


def test_ignore_query_names_are_validated() -> None:
    assert normalize_ignore_query([" v ", "_", "v", ""]) == ["_", "v"]
    assert normalize_ignore_query(["*"]) == ["*"]
    with pytest.raises(ValidationError, match="alone"):
        normalize_ignore_query(["*", "v"])
    with pytest.raises(ValidationError, match="not a query parameter"):
        normalize_ignore_query(["a=b"])
    with pytest.raises(ValidationError, match="at most 20"):
        normalize_ignore_query([f"p{i}" for i in range(21)])


# --- matching and locators --------------------------------------------------------------


def test_strip_query_keeps_everything_else_byte_for_byte() -> None:
    url = f"{CDN}/a.js?v=123&lang=en%20GB&_=9&flag#frag"
    assert strip_query(url, ["v", "_"]) == f"{CDN}/a.js?lang=en%20GB&flag#frag"
    assert strip_query(url, ["*"]) == f"{CDN}/a.js#frag"
    assert strip_query(url, []) == url
    assert strip_query(f"{CDN}/a.js", ["v"]) == f"{CDN}/a.js"
    # Names are compared decoded, the way servers read them.
    assert strip_query(f"{CDN}/a.js?cache%5Fbust=1&x=2", ["cache_bust"]) == f"{CDN}/a.js?x=2"
    assert strip_query(f"{CDN}/a.js?v=1", ["v"]) == f"{CDN}/a.js"


def test_the_longest_prefix_governs_then_the_origin() -> None:
    origin = _policy(PolicyKind.ORIGIN, CDN)
    sdk = _policy(PolicyKind.PREFIX, f"{CDN}/sdk/")
    v1 = _policy(PolicyKind.PREFIX, f"{CDN}/sdk/v1/")
    by_hash = _policy(PolicyKind.HASH, SHA_A)
    policies = [by_hash, origin, v1, sdk]
    assert url_policy_for(f"{CDN}/sdk/v1/w.js", policies) is v1
    assert url_policy_for(f"{CDN}/sdk/v2/w.js", policies) is sdk
    assert url_policy_for(f"{CDN}/other.js", policies) is origin
    assert url_policy_for("https://elsewhere.example/w.js", policies) is None
    assert url_policy_for("not a url", [origin]) is None
    # A prefix ends at a path, so a look-alike host never matches.
    assert url_policy_for("https://cdn.vendor.example.evil.test/sdk/v1/w.js", policies) is None


def test_external_locators_drop_the_governing_policy_query_parameters() -> None:
    origin = _policy(PolicyKind.ORIGIN, CDN, ignore_query=["v"])
    exact = _policy(PolicyKind.PREFIX, f"{CDN}/pinned/")
    assert external_locator(f"{CDN}/a.js?v=2&id=7", [origin]) == f"{CDN}/a.js?id=7"
    # The more specific policy governs, and it keeps the query.
    assert external_locator(f"{CDN}/pinned/a.js?v=2", [origin, exact]) == f"{CDN}/pinned/a.js?v=2"
    assert external_locator("https://other.example/a.js?v=2", [origin]) == (
        "https://other.example/a.js?v=2"
    )


def test_describe_policy() -> None:
    assert describe_policy(_policy(PolicyKind.ORIGIN, CDN)) == f"origin policy {CDN}"
    assert describe_policy(_policy(PolicyKind.HASH, SHA_A)) == (f"hash policy sha384:{SHA_A[:16]}…")


# --- evaluation -------------------------------------------------------------------------


def test_without_a_decision_or_policy_a_script_is_pending() -> None:
    verdict = evaluate(_script(), [_v(SHA_A)], has_approved_versions=False, policies=[])
    assert verdict.status is AuthorizationStatus.PENDING
    assert verdict.policy_id is None


def test_a_rejection_beats_every_policy() -> None:
    policies = [
        _policy(PolicyKind.ORIGIN, CDN, ChangePolicy.EXPECTED_TO_CHANGE),
        _policy(PolicyKind.HASH, SHA_A),
    ]
    verdict = evaluate(
        _script(decision=Decision.REJECTED),
        [_v(SHA_A)],
        has_approved_versions=False,
        policies=policies,
    )
    assert verdict.status is AuthorizationStatus.REJECTED
    assert verdict.reason == "rejected by alice"


def test_an_approval_for_any_version_survives_changes() -> None:
    script = _script(decision=Decision.APPROVED, scope=ApprovalScope.ANY_VERSION)
    verdict = evaluate(script, [_v(SHA_B)], has_approved_versions=True, policies=[])
    assert verdict.status is AuthorizationStatus.APPROVED
    assert "any version" in verdict.reason


def test_a_pinned_approval_covers_approved_bodies_only() -> None:
    script = _script(decision=Decision.APPROVED, scope=ApprovalScope.PINNED)
    ok = evaluate(script, [_v(SHA_A, approved=True)], has_approved_versions=True, policies=[])
    assert (ok.status, ok.reason) == (AuthorizationStatus.APPROVED, "approved by alice")

    changed = evaluate(script, [_v(SHA_B)], has_approved_versions=True, policies=[])
    assert changed.status is AuthorizationStatus.PENDING
    assert changed.reason == "the body changed since alice approved it (pinned)"

    # A per-script pin is deliberate: a broad origin policy doesn't override it...
    origin = _policy(PolicyKind.ORIGIN, CDN, ChangePolicy.EXPECTED_TO_CHANGE)
    pinned = evaluate(script, [_v(SHA_B)], has_approved_versions=True, policies=[origin])
    assert pinned.status is AuthorizationStatus.PENDING
    # ...but a hash policy approves that exact body.
    by_hash = _policy(PolicyKind.HASH, SHA_B)
    covered = evaluate(
        script,
        [_v(SHA_A, approved=True), _v(SHA_B)],
        has_approved_versions=True,
        policies=[by_hash],
    )
    assert covered.status is AuthorizationStatus.APPROVED
    assert covered.policy_id == by_hash.id
    assert "a newer body matches hash policy" in covered.reason


def test_hash_policies_approve_exact_bodies_including_inline_ones() -> None:
    inline = _script("https://shop.example/#inline-0", ScriptKind.INLINE)
    by_hash = _policy(PolicyKind.HASH, SHA_A)
    verdict = evaluate(inline, [_v(SHA_A)], has_approved_versions=False, policies=[by_hash])
    assert verdict.status is AuthorizationStatus.APPROVED
    assert verdict.policy_id == by_hash.id
    # Every current body has to match.
    mixed = evaluate(
        inline, [_v(SHA_A), _v(SHA_B)], has_approved_versions=False, policies=[by_hash]
    )
    assert mixed.status is AuthorizationStatus.PENDING
    # URL policies never apply to inline code.
    origin = _policy(PolicyKind.ORIGIN, "https://shop.example", ChangePolicy.EXPECTED_TO_CHANGE)
    assert (
        evaluate(inline, [_v(SHA_B)], has_approved_versions=False, policies=[origin]).status
        is AuthorizationStatus.PENDING
    )


def test_expected_to_change_policies_approve_any_body() -> None:
    origin = _policy(PolicyKind.ORIGIN, CDN, ChangePolicy.EXPECTED_TO_CHANGE)
    for current in ([], [_v(SHA_A)], [_v(SHA_B)]):
        verdict = evaluate(_script(), current, has_approved_versions=False, policies=[origin])
        assert verdict.status is AuthorizationStatus.APPROVED
        assert verdict.policy_id == origin.id
        assert verdict.approve == ()


def test_pinning_policies_trust_the_first_body_then_flag_changes() -> None:
    prefix = _policy(PolicyKind.PREFIX, f"{CDN}/sdk/")
    script = _script()

    none_yet = evaluate(script, [], has_approved_versions=False, policies=[prefix])
    assert none_yet.status is AuthorizationStatus.PENDING
    assert "none has been fetched yet" in none_yet.reason

    first = _v(SHA_A)
    tofu = evaluate(script, [first], has_approved_versions=False, policies=[prefix])
    assert tofu.status is AuthorizationStatus.APPROVED
    assert tofu.approve == (first.id,)
    assert tofu.reason.endswith("pinned to the first body seen")

    again = evaluate(
        script, [_v(SHA_A, approved=True)], has_approved_versions=True, policies=[prefix]
    )
    assert again.status is AuthorizationStatus.APPROVED
    assert again.approve == ()

    changed = evaluate(script, [_v(SHA_B)], has_approved_versions=True, policies=[prefix])
    assert changed.status is AuthorizationStatus.PENDING
    assert changed.policy_id == prefix.id
    assert changed.reason == f"the body changed since prefix policy {CDN}/sdk/ pinned it"

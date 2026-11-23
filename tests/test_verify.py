"""Executable acceptance tests for the TLS certificate verifier.

The first ten tests lock the ten security defects described in README.md; the
remaining five cover exact matching, wildcard scope, both validity boundaries,
trust-anchor termination, and stateless batching.  These tests are immutable:
only tls/verify.py may change.
"""

import re

from tls.verify import (
    chain_ok,
    fingerprint,
    hostname_match,
    parse_cert,
    pin_ok,
    validity_ok,
    validate_policy,
    verify_batch,
)


def make_cert(
    subject,
    issuer,
    serial="01",
    not_before="2026-01-01T00:00:00",
    not_after="2027-01-01T00:00:00",
    key="key-1",
    signer="self",
    san=(),
    extensions=None,
):
    """Build the text form accepted by parse_cert."""
    lines = [
        "subject=" + subject,
        "issuer=" + issuer,
        "serial=" + serial,
        "not_before=" + not_before,
        "not_after=" + not_after,
        "key=" + key,
        "signer=" + signer,
    ]
    if san:
        lines.append(
            "ext.subjectAltName=" + ",".join("DNS:" + name for name in san)
        )
    for name, value in (extensions or {}).items():
        lines.append("ext." + name + "=" + value)
    return "\n".join(lines) + "\n"


def build_chain(depth, leaf_host="app.example.com"):
    """Return [(cert_text, parsed_cert), ...] ordered leaf first, root last."""
    root_level = depth - 1
    root_text = make_cert(
        subject="Level " + str(root_level),
        issuer="Level " + str(root_level),
        serial=format(root_level, "02x"),
        key="key-" + str(root_level),
        signer="self",
    )
    built = [(root_text, parse_cert(root_text))]

    for level in range(depth - 2, -1, -1):
        _, parent = built[-1]
        subject = leaf_host if level == 0 else "Level " + str(level)
        text = make_cert(
            subject=subject,
            issuer=parent["subject"],
            serial=format(level, "02x"),
            key="key-" + str(level),
            signer=fingerprint(parent),
            san=(leaf_host,) if level == 0 else (),
        )
        built.append((text, parse_cert(text)))

    built.reverse()
    return built


def make_policy(roots, pins=None, now="2026-06-01T00:00:00"):
    """Build a strict policy; roots may be parsed certs or cert text."""
    policy = {
        "roots": roots,
        "now": now,
        "check_hostname": True,
        "allow_unknown_roots": False,
        "max_validity_days": 400,
        "max_chain_length": 4,
    }
    if pins is not None:
        policy["pins"] = pins
    return policy


def signed_leaf(parent, subject, san, serial="99", key="leaf-key"):
    """Build a leaf signed by parent, returning (text, parsed)."""
    text = make_cert(
        subject=subject,
        issuer=parent["subject"],
        serial=serial,
        key=key,
        signer=fingerprint(parent),
        san=san,
    )
    return text, parse_cert(text)


def test_wildcard_does_not_cross_dot_boundaries():
    """缺陷 1：通配符跨点，a.b.example.com 不得命中一级通配。"""
    assert hostname_match("*.example.com", "a.example.com") is True
    assert hostname_match("*.example.com", "a.b.example.com") is False
    assert hostname_match("*.example.com", "example.com") is False


def test_hostname_suffix_bypass_is_rejected():
    """缺陷 2：endswith 后缀比较，evil-example.com 不得命中 example.com。"""
    assert hostname_match("example.com", "example.com") is True
    assert hostname_match("example.com", "evil-example.com") is False
    assert hostname_match("example.com", "example.com.evil") is False
    assert hostname_match("example.com", "sub.example.com") is False


def test_validity_expiry_is_checked():
    """缺陷 3：只比较起始时间，过期证书不得通过。"""
    assert (
        validity_ok(
            "2026-01-01T00:00:00",
            "2026-06-30T23:59:59",
            "2026-12-31T00:00:00",
        )
        is False
    )
    assert (
        validity_ok(
            "2026-01-01T00:00:00",
            "2026-06-30T23:59:59",
            "2026-03-01T00:00:00",
        )
        is True
    )


def test_validity_strings_use_chronological_order():
    """缺陷 4：字符串比较日期，跨月顺序错。"""
    assert (
        validity_ok(
            "2026-9-30T00:00:00",
            "2026-10-31T23:59:59",
            "2026-10-1T00:00:00",
        )
        is True
    )
    assert (
        validity_ok(
            "2026-10-1T00:00:00",
            "2026-11-30T23:59:59",
            "2026-9-30T00:00:00",
        )
        is False
    )


def test_parse_cert_authorizes_subject_alt_names():
    """缺陷 5：只认通用名，主体备用名称里的主机被漏掉。"""
    root_text = make_cert(
        subject="Test Root",
        issuer="Test Root",
        serial="a1",
        key="root-key",
        signer="self",
    )
    root = parse_cert(root_text)

    leaf_text, leaf = signed_leaf(
        root, "wrong.example.com", ("app.example.com",)
    )
    assert leaf["subject"] == "wrong.example.com"
    assert leaf["san"] == ["app.example.com"]

    policy = make_policy([root])
    accepted = verify_batch(
        [
            {
                "host": "app.example.com",
                "cert": leaf_text,
                "chain": [leaf_text, root_text],
            }
        ],
        policy,
    )
    assert accepted["results"][0]["hostname_ok"] is True
    assert accepted["results"][0]["ok"] is True

    cn_only_text, _ = signed_leaf(
        root,
        "app.example.com",
        ("other.example.com",),
        serial="02",
        key="leaf-key-2",
    )
    rejected = verify_batch(
        [
            {
                "host": "app.example.com",
                "cert": cn_only_text,
                "chain": [cn_only_text, root_text],
            }
        ],
        policy,
    )
    assert rejected["results"][0]["hostname_ok"] is False


def test_chain_requires_order_and_signer_relation():
    """缺陷 6：链里出现任意受信根就通过，不校验顺序与签名关系。"""
    entries = build_chain(3)
    chain = [parsed for _, parsed in entries]
    root = chain[-1]

    assert chain_ok(chain, [root]) is True

    reordered = [chain[1], chain[0], chain[2]]
    assert chain_ok(reordered, [root]) is False

    tampered = dict(chain[0])
    tampered["signer"] = "0" * 64
    assert chain_ok([tampered, chain[1], chain[2]], [root]) is False

    root_in_middle = [chain[0], chain[2], chain[1]]
    assert chain_ok(root_in_middle, [root]) is False

    long_entries = build_chain(5)
    long_chain = [parsed for _, parsed in long_entries]
    assert chain_ok(long_chain, [long_chain[-1]]) is False


def test_chain_rejects_untrusted_self_signed_root():
    """缺陷 7：自签证书直接充当受信根。"""
    rogue_text = make_cert(
        subject="rogue.example.com",
        issuer="rogue.example.com",
        serial="aa",
        key="rogue-key",
        signer="self",
    )
    rogue = parse_cert(rogue_text)
    leaf_text, leaf = signed_leaf(
        rogue,
        "victim.example.com",
        ("victim.example.com",),
        serial="bb",
        key="victim-key",
    )

    assert chain_ok([leaf, rogue], []) is False
    assert chain_ok([leaf, rogue], [rogue]) is True


def test_fingerprint_covers_whole_certificate():
    """缺陷 8：只哈希序列号，同序列号的不同证书指纹相同。"""
    a_text = make_cert(
        subject="a.example.com",
        issuer="Test Root",
        serial="abcd",
        key="key-a",
        signer="1" * 64,
        san=("a.example.com",),
    )
    b_text = make_cert(
        subject="b.example.com",
        issuer="Test Root",
        serial="abcd",
        key="key-b",
        signer="1" * 64,
        san=("b.example.com",),
    )
    a = parse_cert(a_text)
    b = parse_cert(b_text)

    assert fingerprint(a) == fingerprint(a)
    assert fingerprint(a) != fingerprint(b)
    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint(a)) is not None


def test_pin_comparison_is_exact():
    """缺陷 9：指纹前缀比较，短前缀也能通过。"""
    text = make_cert(
        subject="app.example.com",
        issuer="Test Root",
        serial="01",
        key="key",
        signer="2" * 64,
        san=("app.example.com",),
    )
    cert = parse_cert(text)
    fp = fingerprint(cert)

    assert pin_ok(cert, []) is True
    assert pin_ok(cert, ["sha256:" + fp]) is True
    assert pin_ok(cert, [fp]) is True
    assert pin_ok(cert, [text]) is True
    assert pin_ok(cert, ["sha256:" + fp[:16]]) is False
    assert pin_ok(cert, ["sha256:" + "0" * 64]) is False


def test_batch_does_not_leak_hostname_between_peers():
    """缺陷 10：后一个连接沿用前一个连接的主机名。"""
    entries = build_chain(2, leaf_host="a.example.com")
    root_text, root = entries[-1]
    a_text = entries[0][0]
    b_text, _ = signed_leaf(
        root,
        "b.example.com",
        ("b.example.com",),
        serial="bb",
        key="key-b",
    )

    policy = make_policy([root])
    peers = [
        {"host": "a.example.com", "cert": a_text, "chain": [a_text, root_text]},
        {"host": "b.example.com", "cert": b_text, "chain": [b_text, root_text]},
    ]
    result = verify_batch(peers, policy)

    assert result["ok"] is True
    assert result["failed"] == []
    assert [item["hostname_ok"] for item in result["results"]] == [True, True]


def test_exact_hostname_matches():
    """合法用例：精确主机名按标签完整相等。"""
    assert hostname_match("app.example.com", "app.example.com") is True
    assert hostname_match("app.example.com", "APP.EXAMPLE.COM") is True
    assert hostname_match("app.example.com", "xapp.example.com") is False
    assert hostname_match("app.example.com", "app.example.com.evil") is False


def test_wildcard_covers_exactly_one_label():
    """合法用例：通配只覆盖一级子域。"""
    assert hostname_match("*.example.com", "cdn.example.com") is True
    assert hostname_match("*.example.com", "a.b.example.com") is False
    assert hostname_match("*.example.com", "example.com") is False
    assert hostname_match("*.example.com", "badexample.com") is False


def test_expired_and_not_yet_valid_are_rejected():
    """合法用例：过期与未生效都拒绝，两个边界都包含。"""
    assert (
        validity_ok(
            "2026-01-01T00:00:00",
            "2026-12-31T23:59:59",
            "2025-12-31T23:59:59",
        )
        is False
    )
    assert (
        validity_ok(
            "2026-01-01T00:00:00",
            "2026-12-31T23:59:59",
            "2027-01-01T00:00:00",
        )
        is False
    )
    assert (
        validity_ok(
            "2026-01-01T00:00:00",
            "2026-12-31T23:59:59",
            "2026-01-01T00:00:00",
        )
        is True
    )
    assert (
        validity_ok(
            "2026-01-01T00:00:00",
            "2026-12-31T23:59:59",
            "2026-12-31T23:59:59",
        )
        is True
    )


def test_chain_must_end_at_trusted_root():
    """合法用例：链必须终止于受信根。"""
    entries = build_chain(3)
    chain = [parsed for _, parsed in entries]
    root = chain[-1]

    other_text = make_cert(
        subject="Other Root",
        issuer="Other Root",
        serial="ff",
        key="other-key",
        signer="self",
    )
    other = parse_cert(other_text)

    assert chain_ok(chain, [other]) is False
    assert chain_ok(chain[:-1], [root]) is False
    assert chain_ok(chain, [root]) is True


def test_batch_runs_are_independent_and_policy_is_strict():
    """合法用例：两批独立校验与单独校验相同，且策略校验严格。"""
    entries = build_chain(2, leaf_host="one.example.com")
    root_text, root = entries[-1]
    one_text = entries[0][0]
    two_text, _ = signed_leaf(
        root,
        "two.example.com",
        ("two.example.com",),
        serial="22",
        key="key-two",
    )

    policy = make_policy([root])
    peer_one = {
        "host": "one.example.com",
        "cert": one_text,
        "chain": [one_text, root_text],
    }
    peer_two = {
        "host": "two.example.com",
        "cert": two_text,
        "chain": [two_text, root_text],
    }

    both = verify_batch([peer_one, peer_two], policy)
    only_one = verify_batch([peer_one], policy)
    only_two = verify_batch([peer_two], policy)

    assert both["ok"] is True
    assert both["failed"] == []
    assert both["results"][0] == only_one["results"][0]
    assert both["results"][1] == only_two["results"][0]

    assert validate_policy(policy) == []
    bad = dict(
        policy,
        allow_unknown_roots=True,
        check_hostname=False,
        max_validity_days=0,
    )
    problems = validate_policy(bad)
    assert "unknown-roots-allowed" in problems
    assert "hostname-not-checked" in problems
    assert "validity-window-zero" in problems

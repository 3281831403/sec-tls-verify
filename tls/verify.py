"""TLS certificate verification: executable specification.

The exercise models a deliberately small, text-based certificate format so the
whole verifier can be written with the standard library only.  A certificate
is a sequence of ``name=value`` lines::

    subject=app.example.com
    issuer=Example Intermediate
    serial=0a1b2c3d
    not_before=2026-01-01T00:00:00
    not_after=2027-01-01T00:00:00
    key=leaf-key-1
    signer=<64 lowercase hex, or self for a self-signed certificate>
    ext.subjectAltName=DNS:app.example.com,DNS:www.example.com
    ext.keyUsage=digitalSignature

``subject`` and ``issuer`` are common names; an optional ``CN=`` prefix is
stripped.  ``signer`` is the SHA-256 fingerprint (see :func:`fingerprint`) of
the issuing certificate, which is how this simplified format binds a child to
its issuer without a crypto library.  A self-signed certificate uses the
literal ``self``.  ``ext.*`` lines are extensions; ``ext.subjectAltName`` is
the subject alternative name extension and carries comma-separated DNS names.

All functions are deterministic, offline and standard-library only.  They must
not mutate their arguments and must not raise for ordinary verification
failures unless a docstring says otherwise.  Comparisons have tolerance 0:
names are only case-folded where stated, there is no prefix, suffix, substring,
IDNA, trailing-dot, whitespace or wildcard-crossing matching.
"""

import hashlib
import re
from datetime import datetime, timezone

__all__ = [
    "hostname_match",
    "validity_ok",
    "parse_cert",
    "chain_ok",
    "fingerprint",
    "pin_ok",
    "validate_policy",
    "verify_batch",
]

# A leaf plus at most three intermediates/roots.  Longer chains are rejected.
MAX_CHAIN_LENGTH = 4
SHA256_HEX_LEN = 64

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_ISO_RE = re.compile(
    r"^(\d{4})-(\d{1,2})-(\d{1,2})"
    r"(?:[T ](\d{1,2}):(\d{2})(?::(\d{2}))?)?$"
)


def _parse_time(value):
    """Parse a naive UTC ``datetime`` from a datetime or an ISO-like string.

    Accepted string forms: ``YYYY-M-D``, ``YYYY-M-DTHH:MM`` and
    ``YYYY-M-DTHH:MM:SS`` with an optional space instead of ``T``.  Aware
    datetimes are converted to UTC and made naive.  Raises ``ValueError`` for
    anything unparsable and ``TypeError`` for a value of an unusable type.
    """
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    if not isinstance(value, str):
        raise TypeError("datetime or ISO-8601 string required")
    match = _ISO_RE.match(value)
    if match is None:
        raise ValueError("unparsable date/time: %r" % (value,))
    year, month, day, hour, minute, second = match.groups()
    return datetime(
        int(year),
        int(month),
        int(day),
        int(hour) if hour is not None else 0,
        int(minute) if minute is not None else 0,
        int(second) if second is not None else 0,
    )


def hostname_match(pattern: str, host: str) -> bool:
    """Return True only when ``pattern`` matches the DNS name ``host``.

    Both inputs are compared case-insensitively (ASCII lower-case); no other
    normalization is applied: surrounding whitespace, a trailing dot, IDNA
    labels and percent escapes are not rewritten.  Return False for non-string
    or empty inputs.

    - Without a wildcard, the match is exact: ``example.com`` matches only
      ``example.com``, never ``evil-example.com``, ``sub.example.com`` or
      ``example.com.evil``.  Suffix and substring comparison are forbidden.
    - A wildcard is supported only as the complete left-most label:
      ``*.example.com``.  It matches exactly one additional label
      (``cdn.example.com``) and never the bare base domain (``example.com``),
      a deeper name (``a.b.example.com``), or a look-alike
      (``badexample.com``).  The wildcard must not consume a dot.
    - A ``*`` anywhere else (``foo*.example.com``, ``*example.com``,
      ``a.*.example.com``) makes the pattern invalid and returns False.

    Tolerance is 0: the match is on label boundaries, not string suffixes.
    """
    if not isinstance(pattern, str) or not isinstance(host, str):
        return False
    if not pattern or not host:
        return False

    pattern_labels = pattern.split(".")
    host_labels = host.split(".")

    # A wildcard is valid only as the complete left-most label; a "*" inside
    # any other label (or a bare empty label) invalidates the whole pattern.
    for label in pattern_labels[1:]:
        if "*" in label or not label:
            return False
    if pattern_labels[0] != "*" and ("*" in pattern_labels[0]
                                     or not pattern_labels[0]):
        return False
    if any(label == "" for label in host_labels):
        return False

    if pattern_labels[0] == "*":
        # The wildcard consumes exactly one label: the host must have exactly
        # one label more than the non-wildcard suffix, never zero or two.
        if len(host_labels) != len(pattern_labels):
            return False
        return all(
            host_labels[i].lower() == pattern_labels[i].lower()
            for i in range(1, len(pattern_labels))
        )

    # No wildcard: every label must be equal; endswith-style suffix matching
    # would let evil-example.com or sub.example.com impersonate example.com.
    if len(host_labels) != len(pattern_labels):
        return False
    return all(
        host_labels[i].lower() == pattern_labels[i].lower()
        for i in range(len(pattern_labels))
    )


def validity_ok(not_before, not_after, now) -> bool:
    """Return True when ``now`` lies inside the inclusive validity window.

    Each argument may be a naive ``datetime`` or an ISO-8601 string of the form
    ``YYYY-M-D``, ``YYYY-M-DTHH:MM`` or ``YYYY-M-DTHH:MM:SS`` (a space may
    replace ``T``; month, day and hour may be unpadded).  Strings without an
    offset are treated as UTC; aware datetimes are converted to UTC and made
    naive before comparison.  Return False for any unparsable value, for a
    window whose start is after its end, or for a mix that cannot be compared.

    Both boundaries are inclusive: ``not_before <= now <= not_after``.  The
    comparison must be chronological.  Comparing the textual forms is a bug:
    for example ``2026-9-30`` is earlier than ``2026-10-1`` even though the
    string ``2026-9-30`` sorts later.  Tolerance is 0: a value one second
    outside the window is rejected.
    """
    try:
        start = _parse_time(not_before)
        end = _parse_time(not_after)
        moment = _parse_time(now)
    except (ValueError, TypeError):
        return False

    # A reversed window can never contain anything.
    if start > end:
        return False

    # Both bounds are checked; checking only not_before would admit an expired
    # certificate.  Comparison is on datetimes, never on the raw strings.
    return start <= moment <= end


def parse_cert(text: str) -> dict:
    """Parse the simplified certificate text into a normalized dict.

    The input is UTF-8 text with one ``name=value`` pair per line.  Blank lines
    are ignored.  Names are case-insensitive; duplicate names and malformed
    lines raise ``ValueError``.  Required names are ``subject``, ``issuer``,
    ``serial``, ``not_before``, ``not_after``, ``key`` and ``signer``.  Any
    other name must start with ``ext.``; unknown top-level names raise
    ``ValueError``.

    Normalization rules:

    - ``subject`` and ``issuer``: trim, strip one optional leading ``CN=``
      (case-insensitive), lower-case; must not be empty afterwards.
    - ``serial``: lower-case hexadecimal, 1 to 64 characters.
    - ``not_before`` / ``not_after``: parsed to naive UTC ``datetime`` using
      the same accepted forms as :func:`validity_ok`; start after end raises
      ``ValueError``.
    - ``key``: opaque non-empty string, trimmed.
    - ``signer``: lower-case ``self`` for a self-signed certificate (requires
      ``subject == issuer``), or exactly 64 lower-case hex characters.
    - ``ext.<name>=<value>``: extension name lower-cased, value trimmed and
      kept as-is.  ``ext.subjectAltName`` is special: split on commas, trim
      each entry, strip an optional ``DNS:`` prefix, lower-case the result and
      collect it in ``san`` in input order; ``IP:`` entries are ignored.
      Other extensions are stored unchanged.

    Return a new dict::

        {
            "subject": str,             # lower-case CN
            "issuer": str,              # lower-case CN
            "serial": str,              # lower-case hex, 1..64 chars
            "not_before": datetime,     # naive UTC
            "not_after": datetime,      # naive UTC
            "san": [str, ...],          # lower-case DNS names, input order
            "extensions": {str: str},   # lower-case extension names
            "key": str,                 # opaque public-key identifier
            "signer": str,              # 64-hex fingerprint or "self"
        }

    This function only parses; it does not validate signatures or trust.  The
    subject alternative name must be parsed from the extension: relying on the
    common name alone loses the names that actually authorize the host.
    Tolerance is 0: no IDNA, trailing-dot, case or whitespace normalization is
    performed beyond the rules above.
    """
    if not isinstance(text, str):
        raise ValueError("certificate text must be a string")

    values = {}
    extensions = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        if "=" not in line:
            raise ValueError("malformed line (no '='): %r" % line)
        name, value = line.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError("malformed line (empty name): %r" % line)
        lname = name.lower()

        if lname.startswith("ext."):
            ext_name = lname[len("ext."):]
            if not ext_name or ext_name in extensions:
                raise ValueError("bad or duplicate extension: %r" % name)
            extensions[ext_name] = value.strip()
        else:
            if lname in values:
                raise ValueError("duplicate name: %r" % name)
            values[lname] = value

    required = ("subject", "issuer", "serial", "not_before",
                "not_after", "key", "signer")
    for name in required:
        if name not in values:
            raise ValueError("missing required field: %s" % name)
    for name in values:
        if name not in required:
            raise ValueError("unknown top-level name: %s" % name)

    def normalize_cn(raw):
        cn = raw.strip()
        if cn[:3].lower() == "cn=":
            cn = cn[3:].strip()
        if not cn:
            raise ValueError("empty common name")
        return cn.lower()

    subject = normalize_cn(values["subject"])
    issuer = normalize_cn(values["issuer"])

    serial = values["serial"].strip().lower()
    if not (1 <= len(serial) <= 64) or _HEX_RE.match(serial) is None:
        raise ValueError("serial must be 1..64 lower-case hex characters")

    try:
        not_before = _parse_time(values["not_before"].strip())
        not_after = _parse_time(values["not_after"].strip())
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid validity date: %s" % exc)
    if not_before > not_after:
        raise ValueError("not_before is after not_after")

    key = values["key"].strip()
    if not key:
        raise ValueError("empty key")

    signer = values["signer"].strip().lower()
    if signer == "self":
        if subject != issuer:
            raise ValueError("self-signed cert requires subject == issuer")
    else:
        if len(signer) != SHA256_HEX_LEN or _HEX_RE.match(signer) is None:
            raise ValueError("signer must be 'self' or 64 hex characters")

    san = []
    san_value = extensions.pop("subjectaltname", None)
    if san_value is not None:
        for entry in san_value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if entry[:3].upper() == "IP:":
                continue
            if entry[:4].upper() == "DNS:":
                entry = entry[4:].strip()
            if entry:
                san.append(entry.lower())

    return {
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "not_before": not_before,
        "not_after": not_after,
        "san": san,
        "extensions": extensions,
        "key": key,
        "signer": signer,
    }


def chain_ok(chain, roots) -> bool:
    """Return True only for an ordered chain ending at a trusted root.

    ``chain`` is a list of parsed certificates, leaf first and trust anchor
    last.  ``roots`` is the configured trust store: a list of parsed
    certificates.  The chain length must be between 1 and MAX_CHAIN_LENGTH (4),
    inclusive; longer chains are rejected even if every link is valid.

    Every adjacent pair must satisfy both relations:

    - ``chain[i]["issuer"] == chain[i + 1]["subject"]`` (case-insensitive);
    - ``chain[i]["signer"] == fingerprint(chain[i + 1])`` exactly, which is the
      simplified signature relation for this format.

    Only the final certificate may terminate the chain, and its fingerprint
    must equal the fingerprint of a certificate in ``roots``.  A trusted root
    that appears earlier in the chain does not make the chain valid.  A
    self-signed certificate is not a trust anchor by itself: it is accepted as
    the final element only when it is explicitly present in ``roots``.
    Reordering, inserting an unrelated certificate, tampering with ``signer``,
    or omitting the root all return False.

    Do not mutate the inputs.  Return False for malformed values instead of
    raising.
    """
    try:
        if not isinstance(chain, list) or not isinstance(roots, list):
            return False
        if not (1 <= len(chain) <= MAX_CHAIN_LENGTH):
            return False

        # Every adjacent pair must be linked both by name and by the
        # fingerprint relation.  A trusted root appearing anywhere other than
        # the last position does not help: the chain is walked in order and no
        # link may be skipped, reordered or signed by an unrelated certificate.
        for i in range(len(chain) - 1):
            child = chain[i]
            parent = chain[i + 1]
            if not isinstance(child, dict) or not isinstance(parent, dict):
                return False
            if child["issuer"].lower() != parent["subject"].lower():
                return False
            if child["signer"] != fingerprint(parent):
                return False

        # Only the final certificate may terminate the chain, and it must be
        # byte-for-byte the same certificate as an entry in the trust store.
        # A self-signed certificate carries no authority on its own.
        terminal = chain[-1]
        terminal_fp = fingerprint(terminal)
        return any(
            isinstance(root, dict) and fingerprint(root) == terminal_fp
            for root in roots
        )
    except (KeyError, TypeError, ValueError):
        return False


def fingerprint(cert) -> str:
    """Return a stable SHA-256 fingerprint of the whole certificate.

    ``cert`` is a dict returned by :func:`parse_cert`.  Build the canonical
    serialization below, encode it as UTF-8, hash it with SHA-256 and return
    the 64-character lower-case hex digest::

        subject=<subject>
        issuer=<issuer>
        serial=<serial>
        not_before=<YYYY-MM-DDTHH:MM:SS>
        not_after=<YYYY-MM-DDTHH:MM:SS>
        san=<comma-joined san list in stored order>
        key=<key>
        signer=<signer>
        ext.<name>=<value>      # one line per extension, sorted by name

    Each line is terminated by a single newline.  The serial alone is not a
    certificate identity: two certificates with the same serial but different
    subject, validity, SAN, key or signer must produce different fingerprints.
    Return the same value for repeated calls with equal input.  Raise
    ``ValueError`` for a value that is not a parsed certificate.
    """
    required_keys = {
        "subject",
        "issuer",
        "serial",
        "not_before",
        "not_after",
        "san",
        "extensions",
        "key",
        "signer",
    }
    if not isinstance(cert, dict) or set(cert) != required_keys:
        raise ValueError("not a parsed certificate")
    if not isinstance(cert["san"], list) or not isinstance(
        cert["extensions"], dict
    ):
        raise ValueError("not a parsed certificate")

    lines = [
        "subject=" + cert["subject"],
        "issuer=" + cert["issuer"],
        "serial=" + cert["serial"],
        "not_before=" + cert["not_before"].isoformat(),
        "not_after=" + cert["not_after"].isoformat(),
        "san=" + ",".join(cert["san"]),
        "key=" + cert["key"],
        "signer=" + cert["signer"],
    ]
    # Extension order must not affect the digest.
    for name in sorted(cert["extensions"]):
        lines.append("ext." + name + "=" + cert["extensions"][name])

    canonical = "".join(line + "\n" for line in lines)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def pin_ok(cert, pins) -> bool:
    """Return True when ``cert`` matches at least one configured pin.

    ``cert`` is a parsed certificate.  ``pins`` is a sequence of strings or
    None; None and an empty sequence mean pinning is not configured and return
    True.  Each pin is tested independently:

    - ``sha256:<64 hex>``: the value after the colon must be exactly 64 hex
      characters and must equal :func:`fingerprint` exactly.
    - a bare 64-hex string: same exact fingerprint comparison.
    - any other string: parsed with :func:`parse_cert` as a pinned
      certificate; it matches only when its fingerprint equals the candidate's
      fingerprint exactly.

    Prefix, substring and case-insensitive hex tricks are forbidden: a short
    prefix such as the first 16 hex characters must not match.  Malformed or
    unparsable pins are skipped, never raised.  Pinning is exact (tolerance 0).
    """
    if pins is None:
        return True
    try:
        if len(pins) == 0:
            return True
        target = fingerprint(cert)
        iter(pins)
    except (ValueError, TypeError):
        return False

    for pin in pins:
        if not isinstance(pin, str) or not pin:
            continue

        candidate = pin
        if pin.startswith("sha256:"):
            candidate = pin[len("sha256:"):]

        if len(candidate) == SHA256_HEX_LEN and _HEX_RE.match(
            candidate
        ) is not None:
            # Exact equality only: startswith-style prefix matching would let a
            # short or partial pin authenticate an unrelated certificate.
            if candidate == target:
                return True
            continue

        # Any other pin form is treated as the text of a pinned certificate.
        try:
            pinned = parse_cert(pin)
        except ValueError:
            continue
        if fingerprint(pinned) == target:
            return True

    return False


def validate_policy(policy) -> list[str]:
    """Return stable problem codes for a verification policy; [] is valid.

    The policy shape is::

        {
            "roots": [cert text or parsed cert, ...],  # required, non-empty
            "now": datetime or ISO-8601 string,        # required
            "check_hostname": bool,                    # default True
            "allow_unknown_roots": bool,               # default False
            "max_validity_days": int,                  # default 365
            "max_chain_length": int,                   # default 4
            "pins": [str, ...],                        # optional
        }

    Check, and emit codes, in this order:

    - ``"roots:missing"``, ``"roots:not-list"`` or ``"roots:empty"``;
    - ``"now:missing"`` or ``"now:invalid"``;
    - ``"unknown-roots-allowed"`` when allow_unknown_roots is true: a policy
      must not accept a chain whose root is not in roots;
    - ``"hostname-not-checked"`` when check_hostname is false (and
      ``"check-hostname:invalid"`` for a non-boolean value): hostname
      verification may not be disabled;
    - ``"validity-window:invalid"`` for a non-integer max_validity_days and
      ``"validity-window-zero"`` when it is zero or negative: a zero window
      disables the validity cap instead of tightening it;
    - ``"max-chain-length:invalid"`` when max_chain_length is not an integer
      in 1..MAX_CHAIN_LENGTH;
    - ``"pins:not-list"`` when pins is present and is not a list.

    Never raise for malformed input; return codes.  Problem strings are stable
    English identifiers so tests and operators can match them exactly.
    """
    problems = []
    if not isinstance(policy, dict):
        policy = {}

    roots = policy.get("roots")
    if "roots" not in policy or roots is None:
        problems.append("roots:missing")
    elif not isinstance(roots, list):
        problems.append("roots:not-list")
    elif len(roots) == 0:
        problems.append("roots:empty")

    if "now" not in policy or policy.get("now") is None:
        problems.append("now:missing")
    else:
        try:
            _parse_time(policy["now"])
        except (ValueError, TypeError):
            problems.append("now:invalid")

    if policy.get("allow_unknown_roots", False) is True:
        problems.append("unknown-roots-allowed")

    if "check_hostname" in policy and not isinstance(
        policy["check_hostname"], bool
    ):
        problems.append("check-hostname:invalid")
    elif policy.get("check_hostname", True) is False:
        problems.append("hostname-not-checked")

    validity_days = policy.get("max_validity_days", 365)
    if isinstance(validity_days, bool) or not isinstance(validity_days, int):
        problems.append("validity-window:invalid")
    elif validity_days <= 0:
        problems.append("validity-window-zero")

    chain_length = policy.get("max_chain_length", MAX_CHAIN_LENGTH)
    if (
        isinstance(chain_length, bool)
        or not isinstance(chain_length, int)
        or not (1 <= chain_length <= MAX_CHAIN_LENGTH)
    ):
        problems.append("max-chain-length:invalid")

    if "pins" in policy and not isinstance(policy["pins"], list):
        problems.append("pins:not-list")

    return problems


def verify_batch(peers, policy) -> dict:
    """Verify independent TLS peers and return a per-peer result.

    ``policy`` is validated with :func:`validate_policy`.  An invalid policy is
    fail-closed: the return value is::

        {"ok": False, "results": [], "failed": [], "errors": [problem, ...]}

    Each peer is::

        {
            "host": str,                    # name the client connected to
            "cert": str,                    # leaf certificate text
            "chain": [str, ...] | None,     # leaf-first cert texts; default [cert]
        }

    For every peer, parse its own leaf and chain (never reuse a previous
    peer's parsed certificate, SAN, hostname or result), then compute:

    - ``hostname_ok``: if the leaf has subjectAltName DNS entries, the host
      must match at least one of them; only when SAN is absent does the
      subject common name act as a fallback.  A present SAN that does not match
      must not fall back to the common name.
    - ``validity_ok``: the leaf's not_before/not_after against policy["now"].
    - ``chain_ok``: the leaf-first chain ends at a trusted policy root, all
      links are ordered and signed, and its length does not exceed
      policy["max_chain_length"] (which itself may not exceed 4).
    - ``pin_ok``: :func:`pin_ok` against policy pins; no pins means True.

    Result shape::

        {
            "ok": bool,                 # every peer ok and no top-level errors
            "results": [
                {
                    "ok": bool,
                    "hostname_ok": bool,
                    "validity_ok": bool,
                    "chain_ok": bool,
                    "pin_ok": bool,
                    "errors": [str, ...],  # "hostname", "validity", "chain",
                                           # "pin" in that order, or
                                           # "cert:invalid"
                },
                ...
            ],
            "failed": [int, ...],       # ascending indices with ok false
            "errors": [str, ...],       # top-level policy/roots errors
        }

    Malformed peers fail individually; they must not abort the batch or affect
    another peer.  A peer whose chain does not start with its own leaf, or
    whose chain cannot be parsed, gets ``"cert:invalid"``.  Each entry in
    ``results`` contains exactly the six keys shown above: do not add a peer
    index, a cached hostname or any other connection-specific state, so a
    single-peer call and the same peer inside a larger batch compare equal.
    All checks are deterministic and offline.
    """
    problems = validate_policy(policy)
    if problems:
        # Invalid policy is fail-closed: no peer is ever evaluated.
        return {"ok": False, "results": [], "failed": [], "errors": problems}

    now = policy["now"]
    max_chain_length = policy.get("max_chain_length", MAX_CHAIN_LENGTH)
    pins = policy.get("pins")

    # Trust store entries may arrive as text or as parsed certificates.
    # Unparsable entries simply cannot authenticate anything.
    trusted_roots = []
    for root in policy["roots"]:
        if isinstance(root, dict):
            trusted_roots.append(root)
        elif isinstance(root, str):
            try:
                trusted_roots.append(parse_cert(root))
            except ValueError:
                continue

    results = []
    failed = []
    try:
        peer_iter = enumerate(peers)
    except TypeError:
        # A non-iterable peer list cannot describe any connection.
        return {"ok": False, "results": [], "failed": [], "errors": []}

    for index, peer in peer_iter:
        if not isinstance(peer, dict):
            results.append(
                {
                    "ok": False,
                    "hostname_ok": False,
                    "validity_ok": False,
                    "chain_ok": False,
                    "pin_ok": False,
                    "errors": ["cert:invalid"],
                }
            )
            failed.append(index)
            continue

        cert_text = peer.get("cert")
        chain_texts = peer.get("chain")
        if chain_texts is None:
            chain_texts = [cert_text]
        if not isinstance(chain_texts, list):
            chain_texts = []

        # Every peer parses its own leaf and chain from scratch; nothing from a
        # previous peer (parsed cert, SAN, hostname or result) is reused.
        try:
            leaf = parse_cert(cert_text)
            chain = [parse_cert(item) for item in chain_texts]
        except (ValueError, TypeError):
            results.append(
                {
                    "ok": False,
                    "hostname_ok": False,
                    "validity_ok": False,
                    "chain_ok": False,
                    "pin_ok": False,
                    "errors": ["cert:invalid"],
                }
            )
            failed.append(index)
            continue

        # The chain must start with this peer's own leaf; a chain borrowed
        # from another connection must never be accepted.
        if not chain or fingerprint(chain[0]) != fingerprint(leaf):
            results.append(
                {
                    "ok": False,
                    "hostname_ok": False,
                    "validity_ok": False,
                    "chain_ok": False,
                    "pin_ok": False,
                    "errors": ["cert:invalid"],
                }
            )
            failed.append(index)
            continue

        # SAN wins when present: a non-matching SAN must not fall back to CN.
        host = peer.get("host", "")
        if leaf["san"]:
            hostname_ok = any(
                hostname_match(name, host) for name in leaf["san"]
            )
        else:
            hostname_ok = hostname_match(leaf["subject"], host)

        validity = validity_ok(
            leaf["not_before"], leaf["not_after"], now
        )

        chain_good = (
            len(chain) <= max_chain_length
            and chain_ok(chain, trusted_roots)
        )
        pin_good = pin_ok(leaf, pins)

        errors = []
        if not hostname_ok:
            errors.append("hostname")
        if not validity:
            errors.append("validity")
        if not chain_good:
            errors.append("chain")
        if not pin_good:
            errors.append("pin")

        result = {
            "ok": not errors,
            "hostname_ok": hostname_ok,
            "validity_ok": validity,
            "chain_ok": chain_good,
            "pin_ok": pin_good,
            "errors": errors,
        }
        results.append(result)
        if result["ok"] is False:
            failed.append(index)

    return {
        "ok": not failed,
        "results": results,
        "failed": failed,
        "errors": [],
    }

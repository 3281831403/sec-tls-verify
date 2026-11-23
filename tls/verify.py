"""TLS certificate verification: executable specification (stubs only).

The exercise models a deliberately small, text-based certificate format so the
whole verifier can be written with the standard library only.  A certificate is
a sequence of ``name=value`` lines::

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
from datetime import datetime, timedelta, timezone

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

_REQUIRED_NAMES = (
    "subject",
    "issuer",
    "serial",
    "not_before",
    "not_after",
    "key",
    "signer",
)

_REQUIRED_CERT_KEYS = (
    "subject",
    "issuer",
    "serial",
    "not_before",
    "not_after",
    "san",
    "extensions",
    "key",
    "signer",
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# YYYY-M-D, optionally followed by THH:MM[:SS] (a space may replace T).
# An optional numeric/Z offset is accepted; offset-less strings are UTC.
_DATETIME_RE = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{1,2})-(?P<day>[0-9]{1,2})"
    r"(?:[T ](?P<hour>[0-9]{1,2}):(?P<minute>[0-9]{2})"
    r"(?::(?P<second>[0-9]{2}))?)?"
    r"(?P<tz>Z|[+-][0-9]{2}:?[0-9]{2})?$"
)

_ASCII_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)


def _ascii_lower(text: str) -> str:
    return text.translate(_ASCII_LOWER)


def _parse_datetime(value):
    """Return a naive UTC ``datetime``, or None when ``value`` is unusable."""
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    if not isinstance(value, str):
        return None
    match = _DATETIME_RE.match(value)
    if match is None:
        return None
    parts = match.groupdict()
    if parts["tz"] is not None and parts["hour"] is None:
        return None
    try:
        hour = int(parts["hour"]) if parts["hour"] is not None else 0
        minute = int(parts["minute"]) if parts["minute"] is not None else 0
        second = int(parts["second"]) if parts["second"] is not None else 0
        parsed = datetime(
            int(parts["year"]),
            int(parts["month"]),
            int(parts["day"]),
            hour,
            minute,
            second,
        )
    except ValueError:
        return None
    tz = parts["tz"]
    if tz is not None:
        if tz == "Z":
            offset_minutes = 0
        else:
            sign = 1 if tz[0] == "+" else -1
            body = tz[1:].replace(":", "")
            offset_hours = int(body[:2])
            offset_rest = int(body[2:])
            if offset_hours > 23 or offset_rest > 59:
                return None
            offset_minutes = sign * (offset_hours * 60 + offset_rest)
        parsed -= timedelta(minutes=offset_minutes)
    return parsed


def _is_parsed_cert(cert) -> bool:
    """Return True when ``cert`` has the shape produced by :func:`parse_cert`."""
    if not isinstance(cert, dict):
        return False
    for key in _REQUIRED_CERT_KEYS:
        if key not in cert:
            return False
    for key in ("subject", "issuer", "serial", "key", "signer"):
        if not isinstance(cert[key], str):
            return False
    for key in ("not_before", "not_after"):
        if not isinstance(cert[key], datetime):
            return False
    if not isinstance(cert["san"], (list, tuple)):
        return False
    if not all(isinstance(name, str) for name in cert["san"]):
        return False
    if not isinstance(cert["extensions"], dict):
        return False
    for name, value in cert["extensions"].items():
        if not isinstance(name, str) or not isinstance(value, str):
            return False
    return True


def _format_datetime(value: datetime) -> str:
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}"
        f"T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
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
    pattern = _ascii_lower(pattern)
    host = _ascii_lower(host)

    if "*" in pattern:
        # Only "*.rest" is a valid wildcard pattern; any other "*" is invalid.
        if not pattern.startswith("*.") or "*" in pattern[2:]:
            return False
        base = pattern[2:]
        if not base:
            return False
        if "*" in host:
            return False
        label, dot, remainder = host.partition(".")
        if not label or not dot:
            return False
        # The wildcard consumes exactly one label; the remainder must match
        # the base exactly on label boundaries.
        return label != "" and remainder == base
    return host == pattern


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
    start = _parse_datetime(not_before)
    end = _parse_datetime(not_after)
    current = _parse_datetime(now)
    if start is None or end is None or current is None:
        return False
    if start > end:
        return False
    return start <= current <= end


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

    fields = {}
    extensions = {}
    san = []
    seen = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" not in line:
            raise ValueError("malformed certificate line: %r" % (raw_line,))
        raw_name, _, raw_value = line.partition("=")
        name = raw_name.strip().lower()
        if not name:
            raise ValueError("malformed certificate line: %r" % (raw_line,))
        if name in seen:
            raise ValueError("duplicate certificate field: %r" % (name,))
        seen.add(name)

        raw_value = raw_value.strip()
        if name in _REQUIRED_NAMES:
            fields[name] = raw_value
        elif name.startswith("ext."):
            ext_name = name[len("ext."):]
            if not ext_name:
                raise ValueError("malformed extension name")
            value = raw_value
            if ext_name == "subjectaltname":
                for entry in value.split(","):
                    entry = entry.strip()
                    if not entry:
                        continue
                    lowered = entry.lower()
                    if lowered.startswith("ip:"):
                        continue
                    if lowered.startswith("dns:"):
                        entry = entry[len("dns:"):].strip()
                    if not entry:
                        continue
                    san.append(entry.lower())
            else:
                extensions[ext_name] = value
        else:
            raise ValueError("unknown certificate field: %r" % (name,))

    for name in _REQUIRED_NAMES:
        if name not in fields:
            raise ValueError("missing required certificate field: %r" % (name,))

    def _name_field(field):
        value = fields[field].strip()
        if value[:3].lower() == "cn=":
            value = value[3:].strip()
        value = value.lower()
        if not value:
            raise ValueError("empty %s" % (field,))
        return value

    subject = _name_field("subject")
    issuer = _name_field("issuer")

    raw_serial = fields["serial"].strip()
    if not _HEX_RE.fullmatch(raw_serial) or len(raw_serial) > SHA256_HEX_LEN:
        raise ValueError("invalid serial")
    serial = raw_serial.lower()

    not_before = _parse_datetime(fields["not_before"].strip())
    not_after = _parse_datetime(fields["not_after"].strip())
    if not_before is None or not_after is None:
        raise ValueError("invalid validity window")
    if not_before > not_after:
        raise ValueError("validity window starts after it ends")

    key = fields["key"].strip()
    if not key:
        raise ValueError("empty key")

    raw_signer = fields["signer"]
    if raw_signer == "self":
        if subject != issuer:
            raise ValueError("self-signed certificate must have subject == issuer")
        signer = "self"
    elif _HEX64_RE.fullmatch(raw_signer):
        signer = raw_signer
    else:
        raise ValueError("invalid signer")

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
    if not isinstance(chain, (list, tuple)):
        return False
    if not isinstance(roots, (list, tuple)):
        return False
    if not 1 <= len(chain) <= MAX_CHAIN_LENGTH:
        return False
    if not all(_is_parsed_cert(cert) for cert in chain):
        return False
    if not all(_is_parsed_cert(cert) for cert in roots):
        return False

    # Every adjacent pair must be ordered by issuer and bound by signature.
    for current, parent in zip(chain, chain[1:]):
        if _ascii_lower(current["issuer"]) != _ascii_lower(parent["subject"]):
            return False
        if current["signer"] != fingerprint(parent):
            return False

    # Only the final certificate terminates the chain, and only when it is
    # explicitly present in the trust store.
    anchor_fingerprint = fingerprint(chain[-1])
    return any(fingerprint(root) == anchor_fingerprint for root in roots)


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
    if not _is_parsed_cert(cert):
        raise ValueError("not a parsed certificate")

    lines = [
        "subject=" + cert["subject"],
        "issuer=" + cert["issuer"],
        "serial=" + cert["serial"],
        "not_before=" + _format_datetime(cert["not_before"]),
        "not_after=" + _format_datetime(cert["not_after"]),
        "san=" + ",".join(cert["san"]),
        "key=" + cert["key"],
        "signer=" + cert["signer"],
    ]
    for name in sorted(cert["extensions"]):
        lines.append("ext." + name + "=" + cert["extensions"][name])
    serialized = "".join(line + "\n" for line in lines)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


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
    if isinstance(pins, str) or not isinstance(pins, (list, tuple)):
        return False
    if not pins:
        return True
    try:
        candidate = fingerprint(cert)
    except (ValueError, TypeError):
        return False

    for pin in pins:
        if not isinstance(pin, str):
            continue
        value = pin.strip()
        if value[:7].lower() == "sha256:":
            # Exactly 64 hex characters compared to the fingerprint exactly:
            # no case-folding, prefix or substring matching.
            digest = value[7:]
            if _HEX64_RE.fullmatch(digest) and digest == candidate:
                return True
            continue
        if _HEX64_RE.fullmatch(value):
            if value == candidate:
                return True
            continue
        try:
            parsed = parse_cert(value)
        except (ValueError, TypeError):
            continue
        if fingerprint(parsed) == candidate:
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
        return ["roots:missing", "now:missing"]

    if "roots" not in policy:
        problems.append("roots:missing")
    elif not isinstance(policy["roots"], list):
        problems.append("roots:not-list")
    elif not policy["roots"]:
        problems.append("roots:empty")

    if "now" not in policy:
        problems.append("now:missing")
    elif _parse_datetime(policy["now"]) is None:
        problems.append("now:invalid")

    if policy.get("allow_unknown_roots"):
        problems.append("unknown-roots-allowed")

    if "check_hostname" in policy:
        if not isinstance(policy["check_hostname"], bool):
            problems.append("check-hostname:invalid")
        elif policy["check_hostname"] is False:
            problems.append("hostname-not-checked")

    if "max_validity_days" in policy:
        days = policy["max_validity_days"]
        if isinstance(days, bool) or not isinstance(days, int):
            problems.append("validity-window:invalid")
        elif days <= 0:
            problems.append("validity-window-zero")

    if "max_chain_length" in policy:
        length = policy["max_chain_length"]
        if (
            isinstance(length, bool)
            or not isinstance(length, int)
            or not 1 <= length <= MAX_CHAIN_LENGTH
        ):
            problems.append("max-chain-length:invalid")

    if "pins" in policy and policy["pins"] is not None and not isinstance(
        policy["pins"], list
    ):
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
        return {"ok": False, "results": [], "failed": [], "errors": problems}

    now = policy["now"]
    max_chain_length = min(
        policy.get("max_chain_length", MAX_CHAIN_LENGTH), MAX_CHAIN_LENGTH
    )
    wants_hostname = policy.get("check_hostname", True)

    # Roots are re-parsed once per batch; each peer's own material is parsed
    # independently below and never cached across peers.
    roots = []
    for root in policy["roots"]:
        if isinstance(root, dict):
            if _is_parsed_cert(root):
                roots.append(root)
        elif isinstance(root, str):
            try:
                roots.append(parse_cert(root))
            except ValueError:
                continue

    results = []
    failed = []

    for index, peer in enumerate(peers if isinstance(peers, (list, tuple)) else []):
        invalid = {
            "ok": False,
            "hostname_ok": False,
            "validity_ok": False,
            "chain_ok": False,
            "pin_ok": False,
            "errors": ["cert:invalid"],
        }

        if not isinstance(peer, dict):
            results.append(invalid)
            failed.append(index)
            continue

        host = peer.get("host")
        cert_text = peer.get("cert")
        chain_value = peer.get("chain", None)
        if chain_value is None:
            chain_value = [cert_text]

        try:
            if not isinstance(cert_text, str) or not isinstance(chain_value, (list, tuple)):
                raise ValueError("invalid peer certificate")
            if not chain_value or not all(
                isinstance(item, str) for item in chain_value
            ):
                raise ValueError("invalid peer chain")
            leaf = parse_cert(cert_text)
            parsed_chain = [parse_cert(item) for item in chain_value]
            if fingerprint(parsed_chain[0]) != fingerprint(leaf):
                raise ValueError("chain does not start with the leaf")
        except (ValueError, TypeError):
            results.append(invalid)
            failed.append(index)
            continue

        hostname_result = False
        if wants_hostname and isinstance(host, str) and host:
            candidates = leaf["san"] if leaf["san"] else [leaf["subject"]]
            hostname_result = any(
                hostname_match(name, host) for name in candidates
            )

        validity_result = validity_ok(
            leaf["not_before"], leaf["not_after"], now
        )

        chain_result = (
            len(parsed_chain) <= max_chain_length
            and chain_ok(parsed_chain, roots)
        )

        pin_result = pin_ok(leaf, policy.get("pins"))

        errors = []
        if not hostname_result:
            errors.append("hostname")
        if not validity_result:
            errors.append("validity")
        if not chain_result:
            errors.append("chain")
        if not pin_result:
            errors.append("pin")

        ok = hostname_result and validity_result and chain_result and pin_result
        results.append(
            {
                "ok": ok,
                "hostname_ok": hostname_result,
                "validity_ok": validity_result,
                "chain_ok": chain_result,
                "pin_ok": pin_result,
                "errors": errors,
            }
        )
        if not ok:
            failed.append(index)

    return {
        "ok": not failed,
        "results": results,
        "failed": failed,
        "errors": [],
    }

"""Pilot trust bundle, known public test keys, and the opt-in trust policy.

Known public test keys and co-located keyring handling.

This module is additive. ``verify_receipt`` and every existing flag behave exactly as before;
nothing here runs unless the caller passes ``--trust-bundle`` or ``--trust-policy``.

What the pieces establish, and what they do not
-----------------------------------------------
* A *pinned trust bundle* is public verification material (issuer id, key id, public key, validity
  window, status) whose exact bytes were authenticated by a SHA-256 digest the caller obtained
  through a channel independent of the receipts. A bundle without that pin is never used.
* A valid signature shows that the receipt's canonical bytes match the supplied public key. It
  does **not** establish that any particular institution holds or operated that key. Institutional
  signer authenticity is outside what a signature check can show, and every report this module
  decorates says so (``TRUST_LIMITS``).
* ``flag`` and ``strict`` policies recognise known *public demonstration keys* by the SHA-256
  fingerprint of the raw 32-byte public key. Recognising one means "this key's private half is
  published test material", never "this signer is genuine".
* ``strict`` additionally refuses to count a keyring that sits beside the receipts as independent
  trust: such a keyring is supplied by whoever supplied the receipts.

The module imports no producer code. It reads serialized bytes only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import ed25519_points

BUNDLE_FORMAT = "arcs.pilot_trust_bundle.v0.1"
LEGACY_KEYRING_VERSION = "srs.trust_bundle.v0.1"  # the keyring shape verify_receipt consumes

TRUST_LIMITS = (
    "A valid signature shows the receipt bytes match the supplied public key; "
    "institutional signer authenticity is not established by a signature check."
)

POLICIES = ("default", "flag", "strict")

_BUNDLE_MEMBERS = {"bundle_format", "bundle_version", "issuers"}
_ENTRY_REQUIRED = {"issuer_id", "key_id", "public_key", "not_before", "not_after"}
_ENTRY_OPTIONAL = {"algorithm", "status", "withdrawn_at", "signer_metadata"}
_METADATA_MEMBERS = {"service", "custody", "posture"}
_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_PIN_RE = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_NAME_RE = re.compile(
    r"^(d|sk|seed|secret|secretkey|signingkey|pkcs8|private.*|priv.*|secret.*)$"
)
# Only key ARMOUR is matched, never the bare words: custody text such as "private key held in an
# HSM" is ordinary and must not be refused.
_PRIVATE_TEXT_RE = re.compile(
    r"-{2,}\s*BEGIN[\s_-]*[A-Z0-9 _]{0,24}PRIVATE[\s_-]*KEY|-{2,}\s*BEGIN[\s_-]*(?:OPENSSH|ENCRYPTED)",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{64,}={0,2}")

# Public demonstration / fixture keys. Each is an Ed25519 *public* key whose private half is
# published test material (a fixed seed in a public repository or a published proof set). Only
# public keys and labels are recorded here; this module holds and derives no seed.
_KNOWN_TEST_KEYS: tuple[tuple[str, str, str], ...] = (
    ("91jPD_Rk5ijc8F2FXtXgVJyyIRWyzkl3aa_-goDuXqc",
     "public demo signing key from a published proof-path keyring",
     "published proof-path keyrings"),
    ("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
     "SRS signed-receipt test vectors key (issuer:vcp:test)",
     "arcs-srs vectors vendored in this repository"),
    ("WWhzV9-MNoorMSfmcwdiBUcpG9mGKTBkDvd0-9tq5Sk",
     "DAGR FastMCP fixture key (issuer:dagr:fastmcp-fixture)",
     "arcs_verify/contracts/dagr-srs-verification-report-v0-1/golden/trust-bundle.json"),
    ("3rx_-sUvPtM31wfTyS3tBKjxWH1yh0AO6-xYaowwLVE",
     "DAGR report contract v0.2 fixture key (issuer:dagr:report-contract-v0-2)",
     "arcs_verify/contracts/dagr-srs-verification-report-v0-2"),
    ("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
     "DAGR first-run capture key (issuer:dagr:first-run-capture)",
     "arcs-verify-dev packs/srs.mcp.sdk_enforcement/v0.1/implementation/dagr-mcp-first-run (not in this tree)"),
    ("fJ7FYeYVFtb5I8Y6TknRzDxmIQF5XYb3WFQvoTM7B24",
     "DAGR ACPS SDK-enforcement test key (test-issuer:dagr-mcp-120-acps-sdk-enforcement)",
     "arcs-verify-dev vendor/dagr-mcp-core/acps_sdk_enforcement_v0_1/evidence (not in this tree)"),
    ("ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
     "public-publication clean-machine positive test key",
     "arcs-verify-dev packs/public-publication-clean-machine0/trust-bundle.json (not in this tree)"),
    ("cSZR9FC6BbY4mLme9fe6RWMujiUn9_cVzWcexAJMxR4",
     "public-publication refusal test key",
     "arcs-verify-dev vendor/arcs-srs literal producer bundles (not in this tree)"),
    ("5_FioQvsVZr-oZXk3OhLaVaNXSywlj60RsBoXisX8vA",
     "public-publication refused-supported test key",
     "arcs-verify-dev vendor/arcs-srs literal producer bundles (not in this tree)"),
    ("c_ACb8pCzJKghwq76VNMTA3xcdeLYtPixWUspHgwoOk",
     "stranger0 synthetic signer A (issuer:stranger0:synthetic-a)",
     "stranger0/cases/artifacts.json (synthetic fixture)"),
    ("sd2FDVuyx3FYkMORUst2CQeDa5YAnMtx6WIgiENXCwA",
     "stranger0 synthetic self-claimed signer",
     "stranger0/cases/artifacts.json (synthetic fixture)"),
    ("wOMkewpBrccG2j3CYhCHQjis0lkjWpvGdNDyfP6BiFc",
     "stranger0 synthetic rogue re-signing key (rogue-1)",
     "stranger0/cases/artifacts.json (synthetic fixture)"),
    ("83UqOD7dmR8WvVuPfp0CJwlFNL5GjO00WeeezR2tnw4",
     "deferred-sequence fixture key (issuer.test/deferred-op/2026-01)",
     "arcs-verify-dev tests/fixtures/deferred_sequence/issuer-keys.json (not in this tree)"),
)


class TrustBundleError(Exception):
    """A named refusal. ``code`` is stable; the message never contains key material."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _b64url_decode_canonical(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError()
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError()
    return decoded


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_key_fingerprint(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


_KNOWN_BY_FINGERPRINT: dict[str, dict[str, str]] = {}
for _pub, _label, _source in _KNOWN_TEST_KEYS:
    _fp = public_key_fingerprint(_b64url_decode_canonical(_pub))
    _KNOWN_BY_FINGERPRINT[_fp] = {
        "public_key": _pub, "fingerprint": _fp, "label": _label, "source": _source,
    }


def known_public_test_key(public_key: Any) -> dict[str, str] | None:
    """Return the registry entry when ``public_key`` is a known public demonstration key."""

    if not isinstance(public_key, str):
        return None
    try:
        raw = base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32:
        return None
    found = _KNOWN_BY_FINGERPRINT.get(public_key_fingerprint(raw))
    return dict(found) if found else None


# --- private-material refusal ----------------------------------------------------------------


def _name_is_private(name: str) -> bool:
    return bool(_PRIVATE_NAME_RE.match(re.sub(r"[^a-z0-9]", "", name.lower())))


def _refuse_private_members(value: Any) -> None:
    """Refuse any member whose name denotes private material, at any depth."""

    if isinstance(value, dict):
        for name, item in value.items():
            if isinstance(name, str) and _name_is_private(name):
                raise TrustBundleError(
                    "trust_bundle_private_key_refused", "a member names private key material"
                )
            _refuse_private_members(item)
    elif isinstance(value, list):
        for item in value:
            _refuse_private_members(item)


def _normalize_text(value: str) -> str:
    """NFKC-normalise and drop invisible format characters, so a marker cannot hide in them."""

    folded = unicodedata.normalize("NFKC", value)
    folded = "".join("-" if (unicodedata.category(ch) == "Pd" or ch == "\u2212") else ch for ch in folded)
    return "".join(ch for ch in folded if unicodedata.category(ch) not in ("Cf", "Cc", "Zl", "Zp") or ch in " \t\n\r")


_DER_PREFIX_HEX = "302e020100300506032b657004220420"  # fixed head of an Ed25519 PKCS#8 private key
_DER_PREFIX_B64 = "MC4CAQAwBQYDK2VwBCIEI"  # the same head in base64 and base64url (identical characters)
_B64_DER_LEN = 64  # unpadded base64 of the 48-byte PKCS#8 blob
_B64_SEED_PUB_LEN = 86  # unpadded base64 of seed plus public key (64 bytes)
_HEX_SEED_PUB_LEN = 128
_MAX_TEXT = 512  # the field validators allow at most 256 characters; anything longer is refused unscanned


def _der_is_private(raw: bytes) -> bool:
    try:
        serialization.load_der_private_key(raw, password=None)
    except Exception:
        return False
    return True


def _seed_plus_public(raw: bytes) -> bool:
    if len(raw) != 64:
        return False
    try:
        derived = Ed25519PrivateKey.from_private_bytes(raw[:32]).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    except Exception:
        return False
    return derived == raw[32:]


def _b64_window_parses(token: str) -> bool:
    decoders = (base64.urlsafe_b64decode,)  # also accepts the standard alphabet's '+' and '/'
    # Ed25519 PKCS#8: anchored on its fixed head, wherever it starts in the token.
    at = token.find(_DER_PREFIX_B64)
    while at != -1:
        piece = token[at:at + _B64_DER_LEN]
        if len(piece) == _B64_DER_LEN:
            for decode in decoders:
                try:
                    if _der_is_private(decode(piece)):
                        return True
                except (binascii.Error, ValueError):
                    continue
        at = token.find(_DER_PREFIX_B64, at + 1)
    # Seed plus public key has no fixed head: every start offset is tried.
    for start in range(0, len(token) - _B64_SEED_PUB_LEN + 1):
        piece = token[start:start + _B64_SEED_PUB_LEN]
        for decode in decoders:
            try:
                raw = decode(piece + "==")
            except (binascii.Error, ValueError):
                continue
            if _seed_plus_public(raw):
                return True
    return False


def _hex_window_parses(run: str) -> bool:
    run = run.lower()
    at = run.find(_DER_PREFIX_HEX)
    while at != -1:
        piece = run[at:at + 96]
        if len(piece) == 96 and _der_is_private(bytes.fromhex(piece)):
            return True
        at = run.find(_DER_PREFIX_HEX, at + 1)
    for start in range(0, len(run) - _HEX_SEED_PUB_LEN + 1):
        if _seed_plus_public(bytes.fromhex(run[start:start + _HEX_SEED_PUB_LEN])):
            return True
    return False


def _text_holds_private_material(value: str) -> bool:
    """True when free text carries key armour, or a run that actually parses as an Ed25519 private key.

    Detected: an armour line (``-----BEGIN ... PRIVATE KEY-----``), and base64, base64url or hex runs
    that decode to an Ed25519 PKCS#8 key or to a 32-byte seed followed by its own public key, at any
    offset (a glued label or suffix does not hide them), also split into groups joined by blanks,
    colons, dots, commas, semicolons, pipes, a literal backslash-n, or slashes (when the key's own
    base64 holds no slash). Not detected: other key types, base64 groups joined by '-' or '_',
    pieces separated by labels, base32 and base85.
    """

    text = _normalize_text(value)
    if _PRIVATE_TEXT_RE.search(text):
        return True
    views = dict.fromkeys((
        text,
        re.sub(r"(?:\\[nrt])|[\s:.,;|]+", "", text),
        re.sub(r"(?:\\[nrt])|[\s:.,;|/]+", "", text),
    ))
    for view in views:
        for token in _TOKEN_RE.findall(view):
            if len(token) >= _B64_DER_LEN and not re.fullmatch(r"[0-9A-Fa-f]+", token):
                if _b64_window_parses(token.rstrip("=")):
                    return True
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", text)
    return len(hex_only) >= 96 and _hex_window_parses(hex_only)


def _refuse_private_text(value: Any) -> None:
    if isinstance(value, str):
        if len(value) > _MAX_TEXT:
            raise TrustBundleError("trust_bundle_invalid", "a text value is too long")
        if _text_holds_private_material(value):
            raise TrustBundleError(
                "trust_bundle_private_key_refused", "a value contains private key material"
            )
    elif isinstance(value, dict):
        for item in value.values():
            _refuse_private_text(item)
    elif isinstance(value, list):
        for item in value:
            _refuse_private_text(item)


def _decoded_looks_private(raw: bytes) -> bool:
    if len(raw) in (48, 64, 83, 85, 96):  # PKCS8 DER, seed+public, OpenSSH-sized blobs
        return True
    try:
        serialization.load_der_private_key(raw, password=None)
    except Exception:
        return False
    return True


def _public_key_b64url(value: Any) -> str:
    """Normalise an accepted public-key form to canonical base64url of the raw 32 bytes.

    Accepted: canonical base64url (43 chars), a PEM ``PUBLIC KEY`` (SPKI) block, or a public JWK
    (``OKP``/``Ed25519``). Anything that is, or parses as, private material is refused by name.
    """

    if isinstance(value, dict):
        if any(_name_is_private(str(name)) for name in value):
            raise TrustBundleError(
                "trust_bundle_private_key_refused", "a JWK member names private key material"
            )
        if set(value) - {"kty", "crv", "x", "kid", "use", "alg"}:
            raise TrustBundleError("trust_bundle_invalid", "unsupported JWK member")
        if value.get("kty") != "OKP" or value.get("crv") != "Ed25519":
            raise TrustBundleError("trust_bundle_invalid", "JWK is not an Ed25519 OKP key")
        return _public_key_b64url(value.get("x"))
    if not isinstance(value, str) or not value.strip():
        raise TrustBundleError("trust_bundle_invalid", "public_key is not a string")
    if _PRIVATE_TEXT_RE.search(_normalize_text(value)):
        raise TrustBundleError(
            "trust_bundle_private_key_refused", "public_key holds a private key block"
        )
    text = value.strip()
    if "-----BEGIN" in text:
        try:
            loaded = serialization.load_pem_public_key(text.encode("ascii"))
        except Exception as exc:
            raise TrustBundleError("trust_bundle_invalid", "unreadable PEM public key") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise TrustBundleError("trust_bundle_invalid", "PEM public key is not Ed25519")
        return _b64url(
            loaded.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
    try:
        raw = _b64url_decode_canonical(text)
    except Exception as exc:
        raise TrustBundleError("trust_bundle_invalid", "public_key encoding is invalid") from exc
    if len(raw) != 32:
        if _decoded_looks_private(raw):
            raise TrustBundleError(
                "trust_bundle_private_key_refused", "public_key decodes to private key material"
            )
        raise TrustBundleError("trust_bundle_invalid", "public_key is not 32 bytes")
    try:
        point = ed25519_points.decode_point(raw)
        on_curve = ed25519_points.exact_order_l(point)
    except ValueError:
        on_curve = False
    if not on_curve:
        raise TrustBundleError("trust_bundle_invalid", "public_key is not a valid Ed25519 point")
    return text


# --- document validation / building ------------------------------------------------------------


def _parse_instant(value: Any, what: str) -> datetime:
    if not isinstance(value, str) or not _TIME_RE.match(value):
        raise TrustBundleError("trust_bundle_invalid", f"{what} is not an RFC 3339 UTC instant")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TrustBundleError("trust_bundle_invalid", f"{what} is not a real instant") from exc


def _text(value: Any, what: str, limit: int = 256) -> str:
    if (
        not isinstance(value, str) or not value.strip() or len(value) > limit
        or any(ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    ):
        raise TrustBundleError("trust_bundle_invalid", f"{what} is not a bounded text value")
    return value


def _normalize_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise TrustBundleError("trust_bundle_invalid", "an issuer entry is not an object")
    _refuse_private_text({k: v for k, v in entry.items() if k != "public_key"})
    unknown = set(entry) - _ENTRY_REQUIRED - _ENTRY_OPTIONAL
    missing = _ENTRY_REQUIRED - set(entry)
    if unknown or missing:
        raise TrustBundleError("trust_bundle_invalid", "issuer entry members are not the closed set")
    algorithm = entry.get("algorithm", "Ed25519")
    if algorithm != "Ed25519":
        raise TrustBundleError("trust_bundle_invalid", "algorithm must be Ed25519")
    not_before = _parse_instant(entry["not_before"], "not_before")
    not_after = _parse_instant(entry["not_after"], "not_after")
    if not not_after > not_before:
        raise TrustBundleError("trust_bundle_invalid", "validity window is empty or inverted")
    status = entry.get("status", "active")
    if status not in ("active", "withdrawn"):
        raise TrustBundleError("trust_bundle_invalid", "status must be active or withdrawn")
    out: dict[str, Any] = {
        "issuer_id": _text(entry["issuer_id"], "issuer_id"),
        "key_id": _text(entry["key_id"], "key_id"),
        "algorithm": "Ed25519",
        "public_key": _public_key_b64url(entry["public_key"]),
        "not_before": entry["not_before"],
        "not_after": entry["not_after"],
        "status": status,
    }
    if status == "withdrawn":
        _parse_instant(entry.get("withdrawn_at"), "withdrawn_at")
        out["withdrawn_at"] = entry["withdrawn_at"]
    elif "withdrawn_at" in entry:
        raise TrustBundleError("trust_bundle_invalid", "withdrawn_at is only valid when withdrawn")
    metadata = entry.get("signer_metadata", {})
    if not isinstance(metadata, dict) or set(metadata) - _METADATA_MEMBERS:
        raise TrustBundleError("trust_bundle_invalid", "signer_metadata members are not the closed set")
    out["signer_metadata"] = {k: _text(v, f"signer_metadata.{k}", 200) for k, v in metadata.items()}
    return out


def _normalize_document(doc: Any, *, require_format: bool) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise TrustBundleError("trust_bundle_invalid", "bundle is not a JSON object")
    _refuse_private_members(doc)
    _refuse_private_text({k: v for k, v in doc.items() if k != "issuers"})
    allowed = _BUNDLE_MEMBERS
    if set(doc) - allowed or "issuers" not in doc or "bundle_version" not in doc:
        raise TrustBundleError("trust_bundle_invalid", "bundle members are not the closed set")
    if require_format and doc.get("bundle_format") != BUNDLE_FORMAT:
        raise TrustBundleError("trust_bundle_invalid", "bundle_format is not supported")
    if "bundle_format" in doc and doc["bundle_format"] != BUNDLE_FORMAT:
        raise TrustBundleError("trust_bundle_invalid", "bundle_format is not supported")
    issuers = doc["issuers"]
    if not isinstance(issuers, list) or not issuers:
        raise TrustBundleError("trust_bundle_invalid", "issuers must be a non-empty list")
    entries = [_normalize_entry(item) for item in issuers]
    key_ids = [e["key_id"] for e in entries]
    if len(set(key_ids)) != len(key_ids):
        raise TrustBundleError("trust_bundle_invalid", "duplicate key_id")
    return {
        "bundle_format": BUNDLE_FORMAT,
        "bundle_version": _text(doc["bundle_version"], "bundle_version", 64),
        "issuers": entries,
    }


def build_trust_bundle(spec: Any, *, allow_known_test_keys: bool = False) -> bytes:
    """Build the canonical (RFC 8785) bytes of a pilot trust bundle from *public* material only.

    Private key material in any accepted spelling is refused with
    ``trust_bundle_private_key_refused``. Known public test keys are refused with
    ``trust_bundle_known_test_key_refused`` unless ``allow_known_test_keys`` is set (test
    bundles only). The bytes returned are the exact bytes whose SHA-256 is the pin.
    """

    try:
        document = _normalize_document(spec, require_format=False)
    except RecursionError as exc:
        raise TrustBundleError("trust_bundle_invalid", "the spec is nested too deeply") from exc
    if not allow_known_test_keys:
        for entry in document["issuers"]:
            if known_public_test_key(entry["public_key"]) is not None:
                raise TrustBundleError(
                    "trust_bundle_known_test_key_refused",
                    "a listed key is a known public demonstration key",
                )
    try:
        return rfc8785.dumps(document)
    except Exception as exc:  # canonicalisation refusals (for example lone surrogates)
        raise TrustBundleError("trust_bundle_invalid", "the bundle cannot be canonicalised") from exc


def bundle_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- loading a pinned bundle --------------------------------------------------------------------


def _reject_constant(_constant: str) -> Any:
    raise ValueError()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member")
        out[key] = value
    return out


def _normalize_pin(pin: str | None) -> str:
    if pin is None or not str(pin).strip():
        raise TrustBundleError("trust_bundle_pin_missing", "no out-of-band SHA-256 was supplied")
    text = str(pin).strip().lower()
    if text.startswith("sha256:"):
        text = text[len("sha256:"):]
    if not _PIN_RE.match(text):
        raise TrustBundleError("trust_bundle_pin_malformed", "pin is not 64 hex digits")
    return text


@dataclass(frozen=True)
class LoadedTrustBundle:
    sha256: str
    bundle_version: str
    entries: tuple[dict[str, Any], ...]

    @property
    def keyring(self) -> dict[str, Any]:
        """The keyring shape ``verify_receipt`` consumes. Withdrawn entries are never trusted."""

        return {
            "trust_bundle_version": LEGACY_KEYRING_VERSION,
            "issuers": [
                {
                    "algorithm": e["algorithm"], "issuer_id": e["issuer_id"], "key_id": e["key_id"],
                    "not_after": e["not_after"], "not_before": e["not_before"],
                    "public_key": e["public_key"], "trusted": e["status"] == "active",
                }
                for e in self.entries
            ],
        }


def load_pinned_trust_bundle(data: bytes | None, pin: str | None) -> LoadedTrustBundle:
    """Authenticate ``data`` against the out-of-band ``pin``, then validate it.

    The digest is checked before the bytes are parsed, so unauthenticated bytes are never
    interpreted. Every refusal is a :class:`TrustBundleError` with a stable code.
    """

    if data is None:
        raise TrustBundleError("trust_bundle_missing", "the trust bundle could not be read")
    expected = _normalize_pin(pin)
    actual = bundle_sha256(data)
    if not hmac.compare_digest(actual, expected):
        raise TrustBundleError(
            "trust_bundle_digest_mismatch", "bundle bytes do not match the supplied pin"
        )
    try:
        doc = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TrustBundleError("trust_bundle_invalid", "bundle is not strict UTF-8 JSON") from exc
    try:
        normalized = _normalize_document(doc, require_format=True)
    except RecursionError as exc:
        raise TrustBundleError("trust_bundle_invalid", "bundle is nested too deeply") from exc
    for entry, raw in zip(normalized["issuers"], doc["issuers"]):
        if entry["public_key"] != raw["public_key"]:
            raise TrustBundleError(
                "trust_bundle_invalid", "a published bundle must carry canonical base64url keys"
            )
    return LoadedTrustBundle(
        sha256=actual,
        bundle_version=normalized["bundle_version"],
        entries=tuple(normalized["issuers"]),
    )


# --- policy ----------------------------------------------------------------------------------------


def _same_dir(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return a == b


def _is_within(child: Path, parent: Path) -> bool:
    """True when ``parent`` is ``child`` or one of its ancestors, by filesystem identity."""

    return any(_same_dir(candidate, parent) for candidate in (child, *child.parents))


def _dir_forms(path: Path) -> list[Path]:
    """The directory as given (made absolute, ``..`` collapsed) and fully symlink-resolved."""

    return [Path(os.path.abspath(path)).parent, path.resolve().parent]


def keyring_is_co_located(receipt_path: Path, keyring_path: Path) -> bool:
    """True when the keyring lives in the receipt's directory tree, or the receipt in the keyring's.

    Compared by filesystem identity (``samefile``), so letter case on a case-insensitive filesystem
    and symlinks do not matter, and judged for both the path as given and the symlink-resolved
    path, so a symlinked receipt or keyring is judged by where it appears as well as where it
    points. A hard link or a copy of the keyring in another directory cannot be detected and is
    not claimed to be.
    """

    for receipt_dir in _dir_forms(receipt_path):
        for keyring_dir in _dir_forms(keyring_path):
            if _is_within(keyring_dir, receipt_dir) or _is_within(receipt_dir, keyring_dir):
                return True
    return False


def _entry_indexes(keyring: dict[str, Any], key_id: Any) -> list[int]:
    """Every entry carrying ``key_id``. The first is the one the verifier resolves."""

    issuers = keyring.get("issuers")
    if not isinstance(issuers, list):
        return []
    return [i for i, e in enumerate(issuers) if isinstance(e, dict) and e.get("key_id") == key_id]


def _add_codes(report: Any, found: list[tuple[str, str]]) -> None:
    # Some verifier lines report per-occurrence locations; others do not. Add them only where the
    # report already carries the member, so this module never widens a report's shape.
    has_occurrences = hasattr(report, "failure_occurrences")
    for code, location in found:
        report.failure_codes.append(code)
        if has_occurrences:
            report.failure_occurrences.append({"code": code, "location": location})
    report.failure_codes = sorted(dict.fromkeys(report.failure_codes))
    if has_occurrences:
        report.failure_occurrences = sorted(
            report.failure_occurrences, key=lambda o: (o["location"], o["code"])
        )


def refused_material_report_keyring() -> dict[str, Any]:
    """The keyring used when trust material was refused: it resolves nothing."""

    return {"trust_bundle_version": LEGACY_KEYRING_VERSION, "issuers": []}


def apply_trust_policy(
    report: Any,
    receipt: dict[str, Any],
    keyring: dict[str, Any],
    *,
    policy: str,
    material_kind: str,
    bundle: LoadedTrustBundle | None = None,
    material_refusal: TrustBundleError | None = None,
    receipt_path: Path | None = None,
    keyring_path: Path | None = None,
) -> dict[str, Any]:
    """Apply the selected policy to a finished ``VerificationReport`` and describe the result.

    Mutates ``report`` only by (a) adding named failure codes and (b) clearing
    ``issuer_key_trusted`` where the policy refuses the key. It never changes
    ``signature_valid``: the cryptographic result stays what the verifier computed.
    """

    if policy not in POLICIES:
        raise ValueError("unknown trust policy")
    found: list[tuple[str, str]] = []
    material: dict[str, Any] = {"kind": material_kind}
    if bundle is not None:
        material.update(
            pinned_sha256=bundle.sha256, bundle_format=BUNDLE_FORMAT,
            bundle_version=bundle.bundle_version,
        )
    if material_refusal is not None:
        found.append((material_refusal.code, "/trust_bundle"))
        material["refused"] = material_refusal.code

    signature = receipt.get("receipt_signature") if isinstance(receipt, dict) else None
    key_id = signature.get("key_id") if isinstance(signature, dict) else None
    indexes = _entry_indexes(keyring, key_id)
    index = indexes[0] if indexes else None
    entry = keyring["issuers"][index] if index is not None else None
    finding: dict[str, str] | None = None

    window_ended: str | None = None
    if bundle is not None and index is not None:
        source = bundle.entries[index]
        if datetime.now(timezone.utc) > _parse_instant(source["not_after"], ""):
            window_ended = source["not_after"]
        location = f"/trust_bundle/issuers/{index}"
        if source["status"] == "withdrawn":
            found.append(("trust_key_withdrawn", location))
        try:
            issued = _parse_instant_loose(receipt.get("issued_at"))
            inside = (
                _parse_instant(source["not_before"], "") <= issued
                <= _parse_instant(source["not_after"], "")
            )
        except (TrustBundleError, ValueError):
            inside = False
        if not inside:
            found.append(("trust_key_outside_validity_window", location))

    if indexes and policy in ("flag", "strict"):
        # Every entry sharing the key_id is examined, not only the one the verifier resolved: a
        # keyring cannot hide a known test key behind a duplicate key_id.
        for candidate in indexes:
            finding = known_public_test_key(keyring["issuers"][candidate].get("public_key"))
            if finding is not None:
                break
    if len(indexes) > 1 and policy == "strict":
        found.append(("keyring_key_id_ambiguous", "/trust_policy"))
    if finding is not None and policy == "strict":
        found.append(("known_public_test_key", "/trust_policy"))

    co_located = False
    if (
        policy == "strict" and material_kind == "keyring"
        and receipt_path is not None and keyring_path is not None
    ):
        co_located = keyring_is_co_located(receipt_path, keyring_path)
        if co_located:
            found.append(("keyring_co_located_with_receipt", "/trust_policy"))

    _add_codes(report, found)
    refused = {code for code, _ in found} & _TRUST_REFUSING
    if refused:
        report.issuer_key_trusted = False

    out: dict[str, Any] = {
        "policy": policy,
        "trust_material": material,
        "limits": TRUST_LIMITS,
    }
    if window_ended is not None:
        # Informational. Validity is judged at the receipt's own issued_at, which is the signer's
        # assertion; this tells the operator the key's window has since closed.
        out["key_window_ended_before_verification"] = window_ended
    if finding is not None:
        out["known_public_test_key"] = finding
    if policy == "strict":
        out["keyring_co_located_with_receipt"] = co_located
    return out


_TRUST_REFUSING = {
    "trust_key_withdrawn",
    "trust_key_outside_validity_window",
    "known_public_test_key",
    "keyring_co_located_with_receipt",
    "keyring_key_id_ambiguous",
}


def _parse_instant_loose(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --- command line: arcs-verify trust-bundle build ---------------------------------------------------


def cli_main(argv: list[str]) -> int:
    """``arcs-verify trust-bundle build --spec SPEC --out BUNDLE [--allow-known-test-keys]``.

    Reads a JSON spec of public material, writes the canonical bundle bytes (never over an
    existing file) and prints the SHA-256 the owner then distributes out of band. Exit 2 on any
    refusal; the message carries the stable code and never the offending value.
    """

    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="arcs-verify trust-bundle",
        description="Build a pilot trust bundle from PUBLIC verification material only.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="build a bundle from a public-material spec")
    build.add_argument("--spec", required=True, type=Path)
    build.add_argument("--out", required=True, type=Path)
    build.add_argument(
        "--allow-known-test-keys", action="store_true", dest="allow_known_test_keys",
        help="permit known public demonstration keys (test bundles only)",
    )
    args = parser.parse_args(argv)

    def refuse(error: TrustBundleError) -> int:
        print(f"{error.code}: {error.detail}" if error.detail else error.code, file=sys.stderr)
        return 2

    try:
        spec = json.loads(
            args.spec.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, ValueError, RecursionError):
        return refuse(TrustBundleError("trust_bundle_invalid", "the spec could not be read as strict JSON"))
    try:
        data = build_trust_bundle(spec, allow_known_test_keys=args.allow_known_test_keys)
    except TrustBundleError as error:
        return refuse(error)
    try:
        with open(args.out, "xb") as handle:
            handle.write(data)
    except OSError:
        return refuse(TrustBundleError("trust_bundle_invalid", "the output path exists or is not writable"))
    print(f"trust_bundle: {args.out}")
    print(f"trust_bundle_sha256: {bundle_sha256(data)}")
    print(f"trust_basis: {TRUST_LIMITS}")
    return 0

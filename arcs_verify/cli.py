from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import trust_bundle
from .verifier import PUBLIC_PUBLICATION_PROFILE, SUPPORTED_PROFILE_DESCRIPTIONS, verify_receipt

# Projected from the verifier's canonical PROFILE_REGISTRY. There is no
# separately maintained supported-profile set that could drift from what the
# verifier actually routes; --list-profiles is a view over that one registry.
SUPPORTED_PROFILES: dict[str, str] = dict(SUPPORTED_PROFILE_DESCRIPTIONS)

_EXAMPLE = (
    "example:\n"
    "  arcs-verify \\\n"
    "    examples/pass-admission.json \\\n"
    "    --trust-bundle examples/test-trust-bundle.json \\\n"
    "    --trust-bundle-sha256 \"$(cat examples/test-trust-bundle.sha256)\" \\\n"
    "    --profile srs.mcp.sdk_enforcement.v0.1\n"
    "\n"
    "subcommands (each takes --help):\n"
    "  arcs-verify exit-o-origin RECEIPT ...   verify EXIT-O origin authentication from explicit local inputs\n"
    "  arcs-verify receipt-set WORKFLOW        verify every receipt in a DAGR workflow index\n"
    "  arcs-verify deferred-sequence ...       verify a deferred-operation receipt sequence\n"
    "  arcs-verify governed-memory-sequence    verify a governed memory read sequence bundle\n"
    "  arcs-verify ingest-run-sequence ...     verify a dagr.ingest_run.v0.1 receipt sequence\n"
    "  arcs-verify c2pa-native ASSET           recompute a native C2PA validation hermetically\n"
    "  arcs-verify portable-pack ...            create/verify a portable offline receipt package\n"
    "  arcs-verify okf-attested-computation DECLARATION --bundle-root DIR --run RUN.json\n"
    "                                           bind an OKF Attested Computation declaration to its resources\n"
    "\n"
    "exit codes: 0 all results passed; 1 verification failed; 2 usage or\n"
    "source-integrity error (not a verification verdict)."
)


def _default_schema() -> Path:
    return Path(__file__).resolve().parent / "data" / "srs-envelope-v0.2.0.schema.json"


def _print_profiles() -> None:
    for name, description in SUPPORTED_PROFILES.items():
        print(f"{name}\n    {description}")


def build_parser(*, keyring_required: bool = True) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a signed ARCS/SRS receipt against the pinned SRS envelope "
            "schema and a named conformance profile. The verifier reads "
            "serialized bytes only; it imports no producer implementation."
        ),
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "receipt",
        type=Path,
        help="path to the serialized receipt JSON to verify",
    )
    parser.add_argument(
        "--keyring",
        required=keyring_required,
        type=Path,
        help="path to the serialized trust bundle used to resolve the signing key",
    )
    parser.add_argument(
        "--trust-bundle",
        type=Path,
        default=None,
        dest="trust_bundle",
        help=(
            "path to an arcs.pilot_trust_bundle.v0.1 file, used INSTEAD of --keyring. It is "
            "only used together with --trust-bundle-sha256; opt-in, never implied"
        ),
    )
    parser.add_argument(
        "--trust-bundle-sha256",
        default=None,
        dest="trust_bundle_sha256",
        help=(
            "SHA-256 of the trust bundle bytes, obtained out of band (not from the same "
            "place as the receipts). A bundle without a matching pin is refused"
        ),
    )
    parser.add_argument(
        "--trust-policy",
        choices=trust_bundle.POLICIES,
        default=None,
        dest="trust_policy",
        help=(
            "opt-in trust policy. 'flag' reports known public test keys without changing the "
            "verdict; 'strict' also refuses issuer_key_trusted for a known public test key and "
            "for a --keyring stored beside the receipts. Omit for the unchanged default"
        ),
    )
    parser.add_argument(
        "--profile",
        default="srs.mcp.sdk_enforcement.v0.1",
        help=(
            "named conformance profile to evaluate (see --list-profiles); "
            "default: %(default)s"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit the full machine-readable report instead of the line summary",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=_default_schema(),
        help="override the pinned envelope schema file (the schema_digest result still applies)",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        dest="list_profiles",
        help="list the named profiles this verifier evaluates, then exit",
    )
    parser.add_argument(
        "--principal-binding-wire",
        type=Path,
        default=None,
        dest="principal_binding_wire",
        help=(
            "path to an explicit serialized UnresolvedActPrincipal wire (arcs-srs#77 "
            "dagr.act_principal_unresolved.v0.2) to check against a "
            "srs.acps.sdk_enforcement.v0.1 receipt's principal_binding.unresolved_digest "
            "and unresolved_reason (H-B1-22 / principal_binding_digest finding). Without "
            "this flag the finding is not_evaluated, never pass; ignored for every other profile."
        ),
    )
    return parser


def _source_error(kind: str, path: Path, detail: str, *, as_json: bool) -> int:
    """Report a source-integrity problem and return exit code 2.

    A missing or unreadable input is not evidence that a receipt failed
    verification, so it must never surface as exit 1. No traceback is
    printed; the message is stable text (or a stable JSON object under
    --json) suitable for automation.
    """
    if as_json:
        print(
            json.dumps(
                {
                    "source_integrity_error": kind,
                    "path": str(path),
                    "detail": detail,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"source_integrity_error: {kind}", file=sys.stderr)
        print(f"path: {path}", file=sys.stderr)
        print(f"detail: {detail}", file=sys.stderr)
    return 2


class _DuplicateJSONMember(ValueError):
    """An ambiguous JSON object was presented; no verifier findings are valid."""


def _unique_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate member names at every depth, after JSON escape decoding."""
    members: dict[str, object] = {}
    for name, value in pairs:
        if name in members:
            raise _DuplicateJSONMember("duplicate JSON object member")
        members[name] = value
    return members


def _load_json_input(path: Path, role: str, *, as_json: bool) -> tuple[dict | None, int]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, _source_error(f"{role}_not_found", path, "no such file", as_json=as_json)
    except IsADirectoryError:
        return None, _source_error(f"{role}_not_a_file", path, "path is a directory", as_json=as_json)
    except UnicodeDecodeError as exc:
        return None, _source_error(f"{role}_not_utf8", path, str(exc), as_json=as_json)
    except OSError as exc:
        return None, _source_error(f"{role}_unreadable", path, str(exc), as_json=as_json)
    try:
        # json.loads defaults to last-member-wins. For signed SRS inputs this
        # can turn conflicting serialized bytes into an apparently valid receipt.
        # All nested objects, including inside arrays, receive this same guard.
        return json.loads(text, object_pairs_hook=_unique_json_members), 0
    except _DuplicateJSONMember as exc:
        # Input-integrity refusal is not a verification verdict. Emit no
        # Boolean findings or invented cryptographic/profile failure codes.
        return None, _source_error(f"{role}_not_i_json", path, str(exc), as_json=as_json)
    except json.JSONDecodeError as exc:
        return None, _source_error(f"{role}_malformed_json", path, str(exc), as_json=as_json)


def _read_regular_file_bytes(path: Path) -> bytes | None:
    """Bytes of a regular file, or None when it cannot be read (reported as trust_bundle_missing)."""
    try:
        if not path.is_file():
            return None
        return path.read_bytes()
    except OSError:
        return None


def _verify_srs(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--list-profiles" in raw:
        _print_profiles()
        return 0
    bundle_given = any(
        arg == "--trust-bundle" or arg.startswith("--trust-bundle=") for arg in raw
    )
    parser = build_parser(keyring_required=not bundle_given)
    args = parser.parse_args(raw)
    if bundle_given and args.keyring is not None:
        parser.error("--keyring and --trust-bundle are mutually exclusive")
    if args.trust_bundle_sha256 is not None and args.trust_bundle is None:
        parser.error("--trust-bundle-sha256 requires --trust-bundle")
    if (
        args.profile == PUBLIC_PUBLICATION_PROFILE
        and not any(arg == "--schema" or arg.startswith("--schema=") for arg in raw)
    ):
        args.schema = (
            Path(__file__).resolve().parent
            / "data"
            / "srs-envelope-v0.2.1.schema.json"
        )
    receipt, err = _load_json_input(args.receipt, "receipt", as_json=args.as_json)
    if err:
        return err
    loaded_bundle = None
    material_refusal = None
    if args.trust_bundle is not None:
        # Opt-in pinned-bundle path. The bytes are authenticated against the out-of-band pin
        # before they are parsed; any refusal leaves a keyring that resolves nothing, so the
        # receipt fails with a named code instead of being judged against unauthenticated keys.
        try:
            keyring = None
            bundle_bytes = _read_regular_file_bytes(args.trust_bundle)
            loaded_bundle = trust_bundle.load_pinned_trust_bundle(
                bundle_bytes, args.trust_bundle_sha256
            )
            keyring = loaded_bundle.keyring
        except trust_bundle.TrustBundleError as exc:
            material_refusal = exc
            keyring = trust_bundle.refused_material_report_keyring()
    else:
        keyring, err = _load_json_input(args.keyring, "keyring", as_json=args.as_json)
        if err:
            return err
    if not isinstance(receipt, dict):
        return _source_error(
            "receipt_not_an_object",
            args.receipt,
            f"top-level JSON value is {type(receipt).__name__}, not an object",
            as_json=args.as_json,
        )
    if not isinstance(keyring, dict):
        return _source_error(
            "keyring_not_an_object",
            args.keyring,
            f"top-level JSON value is {type(keyring).__name__}, not an object",
            as_json=args.as_json,
        )
    schema_probe, err = _load_json_input(args.schema, "schema", as_json=args.as_json)
    if err:
        return err
    if not isinstance(schema_probe, dict):
        return _source_error(
            "schema_not_an_object",
            args.schema,
            f"top-level JSON value is {type(schema_probe).__name__}, not an object",
            as_json=args.as_json,
        )
    companion_principal_wire = None
    if args.principal_binding_wire is not None:
        companion_principal_wire, err = _load_json_input(
            args.principal_binding_wire, "principal_binding_wire", as_json=args.as_json
        )
        if err:
            return err
        if not isinstance(companion_principal_wire, dict):
            return _source_error(
                "principal_binding_wire_not_an_object",
                args.principal_binding_wire,
                f"top-level JSON value is {type(companion_principal_wire).__name__}, not an object",
                as_json=args.as_json,
            )
    report = verify_receipt(
        receipt,
        keyring,
        schema_path=args.schema,
        selected_profile=args.profile,
        companion_principal_wire=companion_principal_wire,
    )
    policy_block = None
    if args.trust_bundle is not None or args.trust_policy is not None:
        policy_block = trust_bundle.apply_trust_policy(
            report,
            receipt,
            keyring,
            policy=args.trust_policy or "default",
            material_kind="pinned_trust_bundle" if args.trust_bundle is not None else "keyring",
            bundle=loaded_bundle,
            material_refusal=material_refusal,
            receipt_path=args.receipt,
            keyring_path=args.keyring,
        )
    data = report.to_dict()
    if policy_block is not None:
        data["trust_policy"] = policy_block
    if args.as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        for name in ("schema_digest", "envelope", "profile", "raw_content_exclusion", "signature_valid", "issuer_key_resolved", "issuer_key_trusted", "attestation_limits_present"):
            print(f"{name}: {'PASS' if data[name] else 'FAIL'}")
        for name in ("lowering_consistency", "outcome_binding", "principal_binding_digest"):
            if name in data:
                print(f"{name}: {data[name]}")
        print(f"chain_status: {data['chain_status']}")
        for code in data["failure_codes"]:
            print(f"failure_code: {code}")
        if policy_block is not None:
            flagged = policy_block.get("known_public_test_key")
            if flagged is not None:
                print(f"known_public_test_key: FLAG ({flagged['label']}; {flagged['fingerprint']})")
            ended = policy_block.get("key_window_ended_before_verification")
            if ended is not None:
                print(f"key_window_ended_before_verification: {ended}")
            print(f"trust_basis: {policy_block['limits']}")
    return 0 if report.passed else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "trust-bundle":
        return trust_bundle.cli_main(args[1:])
    if args and args[0] == "scitt-registration":
        from .scitt_registration import main as scitt_main

        return scitt_main(args[1:])
    if args and args[0] == "exit-o-origin":
        from .exit_o_origin_cli import main as exit_o_origin_main

        return exit_o_origin_main(args[1:])
    if args and args[0] == "dagr-report":
        from .dagr_report import main as dagr_report_main

        return dagr_report_main(args[1:])
    if args and args[0] == "dagr-report-v0-2":
        from .dagr_report_v0_2 import main as dagr_report_v0_2_main

        return dagr_report_v0_2_main(args[1:])
    if args and args[0] == "receipt-set":
        from .receipt_set import main as receipt_set_main

        return receipt_set_main(args[1:])
    if args and args[0] == "deferred-sequence":
        from .deferred_sequence import main as deferred_sequence_main

        return deferred_sequence_main(args[1:])
    if args and args[0] == "governed-memory-sequence":
        from .governed_memory_sequence import main as governed_memory_sequence_main

        return governed_memory_sequence_main(args[1:])
    if args and args[0] == "ingest-run-sequence":
        from .ingest_run_sequence import main as ingest_run_sequence_main

        return ingest_run_sequence_main(args[1:])
    if args and args[0] == "c2pa-native":
        from .c2pa_native import main as c2pa_native_main

        return c2pa_native_main(args[1:])
    if args and args[0] == "portable-pack":
        from .portable_pack import main as portable_pack_main

        return portable_pack_main(args[1:])
    if args and args[0] == "okf-attested-computation":
        from .okf_attested_computation import main as okf_attested_computation_main

        return okf_attested_computation_main(args[1:])
    return _verify_srs(args)


if __name__ == "__main__":
    raise SystemExit(main())

# ARCS Verify

When an AI runtime acts through a tool boundary, the record of what it was
allowed to do is usually a claim made by the same system that did it. ARCS
Verify is the other half of that story: an independent verifier that checks a
signed receipt against a pinned envelope schema and a named conformance
profile, from serialized bytes alone. It imports nothing from the producer. It
verifies the structure of the evidence and its cryptographic and profile
properties; it does not certify the producing implementation and does not prove
that the original real-world event described by the receipt actually occurred.

This tree is a verifier-only source snapshot. It contains the verifier package,
the verification contracts the command line loads at runtime, user documentation
and synthetic examples. It contains no receipt emitter, no tests and no
development history. It is pre-1.0 and has not been published to a package
index; install it from a checkout.

## Try it in five minutes

You need Python 3.11 or newer. Check first, because macOS still ships 3.9 as
`/usr/bin/python3`:

```bash
python3 --version
```

If it prints 3.10 or lower, install a newer Python (python.org, or
`brew install python@3.12`) and use that interpreter, for example `python3.12`,
in place of `python3` below. No network is needed during verification, and every
input is in this repository.

```bash
git clone https://github.com/thelaplage/arcs-verify-public.git
cd arcs-verify-public
python3 -m venv .venv && source .venv/bin/activate
python -m pip install .

arcs-verify examples/pass-admission.json \
  --trust-bundle examples/test-trust-bundle.json \
  --trust-bundle-sha256 "$(cat examples/test-trust-bundle.sha256)" \
  --profile srs.mcp.sdk_enforcement.v0.1
```

Expected output: eight PASS lines and `chain_status: not_applicable`, exit 0.

Now verify the copy in which one byte of the signature was changed:

```bash
arcs-verify examples/tampered-admission-one-byte.json \
  --trust-bundle examples/test-trust-bundle.json \
  --trust-bundle-sha256 "$(cat examples/test-trust-bundle.sha256)" \
  --profile srs.mcp.sdk_enforcement.v0.1
```

Expected: `signature_valid: FAIL`, `failure_code: signature_invalid`, exit 1.

The examples are synthetic. The signing key is a labelled test key that the
verifier's registry lists as a known public demonstration key, so
`--trust-policy strict` refuses `issuer_key_trusted` for it by design. See
[examples/README.md](examples/README.md) and [docs/QUICKSTART.md](docs/QUICKSTART.md).

Then check real receipts. This re-checks the signed receipts from the
Counterpedia MCP governed-read tests (see [Evidence](#evidence)) under the
**strict** policy: every receipt must pass and every tampered copy must fail.

```bash
python evidence/chat-integrations-2026-11-19/check.py
```

Expected last line: `20 files checked; all expectations held`, exit 0.

**What you have just shown.** A PASS means the receipt's bytes are unchanged
since they were signed under the listed key, and that the receipt meets its
profile's rules. A FAIL on the tampered copy shows the check notices a one-byte
change. Neither result shows that the event described in the receipt really
happened, or that the key belongs to any particular organisation: these are
test keys.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No matching distribution found for jsonschema<5,>=4.26` | Python older than 3.11 (often macOS's `/usr/bin/python3`, 3.9). Recreate the venv with Python 3.11+. |
| `arcs-verify: command not found` | The virtual environment is not active. Run `source .venv/bin/activate` (Windows: `.venv\Scripts\activate`). |
| `issuer_key_trusted: FAIL` on the `examples/` files with `--trust-policy strict` | Expected: the examples use a published demonstration key that strict policy refuses. Use the default policy for them. |
| Exit code `2` | A usage or input problem (wrong path, unreadable file), not a verification verdict. |

One precision worth knowing from the start: the signature covers the receipt's
RFC 8785 canonical JSON content, not the source file's formatting. Reindenting
or reordering keys leaves verification passing; altering any signed field value
breaks it.

## Result semantics

The signed-SRS verifier reports **eight Boolean results** and, separately, a
`chain_status` string. Add `--json` for the full machine-readable report (shape
documented in [docs/REPORT_SCHEMAS.md](docs/REPORT_SCHEMAS.md)).

| Result | Meaning |
|---|---|
| `schema_digest` | The pinned SRS envelope schema file matches the frozen SHA-256. |
| `envelope` | The receipt validates against the pinned SRS envelope JSON Schema. |
| `profile` | The receipt satisfies the requirements of the selected named profile. |
| `raw_content_exclusion` | The receipt carries references and digests only; no raw governed content or credential material is present. |
| `signature_valid` | The Ed25519 signature over the RFC 8785 preimage verifies and the version binding matches the selected profile. |
| `issuer_key_resolved` | The signature `key_id` resolves to an entry in the trust input. |
| `issuer_key_trusted` | The resolved key is marked trusted, its `issuer_id` matches the receipt, and `issued_at` falls inside the key's validity window. |
| `attestation_limits_present` | `attestation_limits` is present and holds non-empty strings. |

`chain_status` is reported separately and is not a ninth Boolean. For a
standalone signed receipt the required value is `not_applicable`: no
cross-artifact chain was in scope. Overall pass requires all eight Booleans true
and `chain_status == not_applicable`. There is no aggregate verified badge, by
design: each result answers one question, and questions the verifier does not
evaluate stay visibly unevaluated. `not_evaluated` is not PASS and
`not_applicable` is not PASS.

| Exit | Meaning |
|---|---|
| `0` | All verifications in scope passed. |
| `1` | Verification failed. |
| `2` | Usage or source-integrity error (unreadable or malformed input). Not a verification verdict. |

## Trust inputs

A valid signature shows that a receipt's canonical bytes match a public key the
verifier was given. It does not show that any particular institution holds that
key. Trust input comes from the verifier's operator, separately from the receipts:

- `--keyring FILE`: a serialized trust bundle.
- `--trust-bundle FILE --trust-bundle-sha256 DIGEST`: a pilot trust bundle whose
  exact bytes are authenticated by a digest obtained out of band.
- `--trust-policy default|flag|strict`: opt-in handling of known public test keys
  and co-located keyrings.
- `--profile NAME`: the named conformance profile (`--list-profiles`).

Details: [docs/PILOT_TRUST_BUNDLE.md](docs/PILOT_TRUST_BUNDLE.md).

## Other subcommands

`arcs-verify --help` lists them. They include `receipt-set`,
`deferred-sequence`, `governed-memory-sequence`, `ingest-run-sequence`,
`portable-pack`, `exit-o-origin`, `c2pa-native`,
`okf-attested-computation`, `dagr-report`, `dagr-report-v0-2`,
`scitt-registration` (experimental, optional extra) and `trust-bundle`. Each
takes `--help`. The default signed-SRS path above is the one whose exit-code
contract is documented; other subcommands do not yet route source problems
uniformly through exit 2.

## Layer boundary

The party that issues a receipt and the party that verifies it are separate
roles. ARCS Verify sits entirely on the verifier side: it reads a serialized
receipt, a serialized trust input and pinned schema bytes, and recomputes every
property from those bytes. It does not depend on the emitting runtime and needs
no access to the issuer's infrastructure. See
[VERIFICATION_BOUNDARIES.md](VERIFICATION_BOUNDARIES.md) and
[docs/PYTHON_API.md](docs/PYTHON_API.md).

## Limitations and claim discipline

- ARCS Verify does not provide operator-independent proof that the original
  record or event was true. That would require an external anchor outside this
  verifier's inputs.
- A valid signature means the signed receipt was not modified after issuance
  under the resolved issuer key. It does not mean the underlying event was true,
  complete or correctly described.
- ARCS Verify makes no certification, no comparative claim and no product
  superlative. It reports structural and cryptographic results and nothing
  beyond them.

## Where this sits

<!-- layer-map -->

| Role | Surface |
|---|---|
| Standard | ARCS |
| Receipt protocol and profiles | SRS |
| Open receipt-emitter/runtime binding | Separate repository; not part of this tree |
| Public reference implementation | ARCS Verify and the examples in this tree |

## Evidence

[evidence/chat-integrations-2026-11-19/](evidence/chat-integrations-2026-11-19/) holds signed test receipts from
the Counterpedia MCP governed-read tests, with tampered copies and a one-command re-check
(`python evidence/chat-integrations-2026-11-19/check.py`). They are signed with throwaway test keys, not a
production trust root.

## License

Apache-2.0. See [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).

`arcs_verify/ed25519_points.py` follows the RFC 8032 section 6 reference code, an IETF
Code Component under the Simplified BSD License; its notice is kept in that file.

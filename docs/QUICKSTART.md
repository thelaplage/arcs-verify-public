# ARCS Verify: five-minute quickstart

Verify a signed receipt from a clean checkout with no undocumented steps. Every
input is committed in this repository and no network access is needed.

## 1. Create a clean virtual environment

Requires Python **3.11 or newer**.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
```

## 2. Install the verifier from this checkout

```bash
python -m pip install .
```

This installs the `arcs-verify` console command from the local source tree. It is
not published to a package index.

## 3. Verify the bundled synthetic receipt

The receipt, the trust bundle and the trust bundle's SHA-256 pin are under
`examples/`. The pin stands in for a digest you would obtain out of band.

```bash
arcs-verify examples/pass-admission.json \
  --trust-bundle examples/test-trust-bundle.json \
  --trust-bundle-sha256 "$(cat examples/test-trust-bundle.sha256)" \
  --profile srs.mcp.sdk_enforcement.v0.1
echo "exit code: $?"   # 0
```

Expected: eight results, each `PASS`, then `chain_status: not_applicable`
(reported separately; not a ninth PASS). Exit code **0**. Add `--json` for the
full report.

## 4. Run the negative check

`examples/tampered-admission-one-byte.json` differs from the receipt above by one
byte inside `receipt_signature.signature`.

```bash
arcs-verify examples/tampered-admission-one-byte.json \
  --trust-bundle examples/test-trust-bundle.json \
  --trust-bundle-sha256 "$(cat examples/test-trust-bundle.sha256)" \
  --profile srs.mcp.sdk_enforcement.v0.1
echo "exit code: $?"   # 1
```

Expected: `signature_valid: FAIL`, a `failure_code: signature_invalid` line, exit
code **1**. Exit `2` signals a usage or unreadable-input error and is not a
verification verdict.

## 5. See the trust policy

```bash
arcs-verify examples/pass-admission.json \
  --trust-bundle examples/test-trust-bundle.json \
  --trust-bundle-sha256 "$(cat examples/test-trust-bundle.sha256)" \
  --profile srs.mcp.sdk_enforcement.v0.1 --trust-policy strict
```

Expected: exit 1, `issuer_key_trusted: FAIL` with code `known_public_test_key`.
The example key is a published demonstration key, and `strict` refuses such keys
by design. `--trust-policy flag` reports it without changing the verdict.

## What a clean result means

A clean signed-receipt result establishes that the receipt matches the pinned SRS
envelope schema and the named profile, and was not modified after issuance under
the resolved, trusted issuer key. It does not certify the producing
implementation and does not prove the underlying event was true. See the
**Limitations and claim discipline** section of the [README](../README.md).

## Where to go next

- [PILOT_TRUST_BUNDLE.md](PILOT_TRUST_BUNDLE.md): building and pinning a trust bundle.
- [PYTHON_API.md](PYTHON_API.md): the same verification embedded in Python.
- [REPORT_SCHEMAS.md](REPORT_SCHEMAS.md): the machine-readable report shapes.
- [../VERIFICATION_BOUNDARIES.md](../VERIFICATION_BOUNDARIES.md): what each result does and does not mean.

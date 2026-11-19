# Examples

All material here is synthetic. Nothing is derived from any real record, person,
organisation or deployment.

| File | What it is |
|---|---|
| `pass-admission.json` | A synthetic signed admission receipt (profile `srs.mcp.sdk_enforcement.v0.1`). |
| `tampered-admission-one-byte.json` | The same receipt with one byte of `receipt_signature.signature` changed (file byte 1245, 1-based: `e` changed to `A`). |
| `trust-bundle-spec.json` | Public-key-only input for `arcs-verify trust-bundle build`. |
| `test-trust-bundle.json` | The resulting pilot trust bundle (`arcs.pilot_trust_bundle.v0.1`), one issuer. |
| `test-trust-bundle.sha256` | SHA-256 of `test-trust-bundle.json`, the out-of-band pin. |

## Test key notice

The only key is the public half of a synthetic demonstration signer
(`issuer:stranger0:synthetic-a`). It is a test key. Treat its private half as
publicly known test material: nothing signed with it carries any authority. The
verifier's `--trust-policy flag` reports it as a known public test key and
`--trust-policy strict` refuses to trust it. No private key material is shipped
in this tree.

## Reproduce

```bash
arcs-verify examples/pass-admission.json --trust-bundle examples/test-trust-bundle.json \
  --trust-bundle-sha256 "$(cat examples/test-trust-bundle.sha256)" --profile srs.mcp.sdk_enforcement.v0.1   # exit 0
arcs-verify examples/tampered-admission-one-byte.json --trust-bundle examples/test-trust-bundle.json \
  --trust-bundle-sha256 "$(cat examples/test-trust-bundle.sha256)" --profile srs.mcp.sdk_enforcement.v0.1   # exit 1, signature_invalid
arcs-verify trust-bundle build --spec examples/trust-bundle-spec.json --out /tmp/rebuilt.json --allow-known-test-keys
cmp /tmp/rebuilt.json examples/test-trust-bundle.json                                                        # identical
```

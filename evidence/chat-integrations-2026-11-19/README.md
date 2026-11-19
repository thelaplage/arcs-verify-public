# Chat-integrations receipt evidence, 2026-11-19

Signed SRS receipts from two offline tests of the Counterpedia MCP governed-read path, with one-byte and one-field
tampered copies and the trust input each set needs. Anyone can re-check them with this repository alone:

```bash
pip install .
python evidence/chat-integrations-2026-11-19/check.py
```

The script checks each trust bundle against its out-of-band SHA-256 pin, then runs `arcs-verify` under the
**strict** trust policy on every file. Every receipt must pass (exit 0), and every tampered copy must fail (exit 1)
with `signature_invalid`. It prints one line per file and exits 0 only if all 20 expectations hold. It imports no
producer code.

## The two sets

**`record-level/`**: one governed session against record `CP-SIG-15` at admission generation
`ADM-EVT-counterpose:CP-SIG-15-0002`. It holds:
- an admitted `get_entry` admission and its outcome;
- a `governed_read` receipt (profile `srs.activity.governed_read.v0.1`) naming that record version, with basis
  snapshot digest `sha256:a3f7ed1f4415744d9c95b3d7b7815a5b1b45d1151ba3c995afc32bdba6dc9a3a`;
- a refused `get_sources` admission, refused before its handler ran.

That record version is the one real ChatGPT and Claude clients were shown through the nine-tool MCP on 2026-11-19.
The client sessions themselves are not part of this bundle.

**`source-level/`**: a governed read of record `EAST-PALESTINE-ASSESSMENT-0001` (profile
`srs.activity.governed_read.v0.2`). The signed receipt carries the record's two Source references (Source id plus
capture hash) and their `source_set_digest`. Its five tampered copies each change one Source id, one capture hash
or the set digest. The verifier recomputes the set digest independently of the signature, so it reports
`source_set_digest_mismatch` (and `source_basis_ref_invalid` for a malformed id) as well as `signature_invalid`.

## Trust input: test keys only

Each `trust/trust-bundle.json` holds one **throwaway test Ed25519 key** generated for that test run. It is not a
production trust root, it does not represent Counterpedia's issuing authority, and receipts verified against it
establish nothing about any production issuer. Its `issuer_id` and the `not_after` date are fixture values. The
matching private keys are not published. `trust-bundle-spec.json` is the input that `arcs-verify trust-bundle`
builds the bundle from. `out-of-band/trust-bundle.sha256` is the pin a verifier would obtain separately; here it
ships beside the bundle, so it shows the mechanism but authenticates nothing on its own.

## What a pass establishes, and what it does not

- **Establishes:** each receipt's bytes are unchanged since signing under the listed test key. Each receipt meets
  its profile's structural rules. For `source-level`, the Source references inside the signature agree with their
  digest.
- **Does not establish:** that the record or its Sources are true, accurate or eligible for publication. It does not
  show that the capture hashes match any capture bytes (this bundle does not include them), or that a Source has a
  SourceEdition identity. It does not establish who the acting principal was (`user_abc123` is a declared fixture
  value) or anything about production issuer trust.
- **Not reproducible from here:** the basis snapshot digests are SHA-256 hashes of admitted-record files in a
  private repository, so a stranger cannot recompute them from public bytes. The receipts are fixture runs of the
  producer at a pinned commit, not live production reads.

Both sets were produced by the Counterpedia MCP producer test suite and are copied here byte for byte.
`SHA256SUMS` covers every file in this folder.

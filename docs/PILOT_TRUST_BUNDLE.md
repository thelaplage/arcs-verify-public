# Pilot trust bundle and trust policy

Status: pilot format `arcs.pilot_trust_bundle.v0.1`. Agent guidance and engineering reference; it
authorizes no publication, key, deployment or admission. Published by the owner, never by this tool.

## What this is, and what it is not

A valid signature shows that a receipt's canonical bytes match the public key the verifier was
given. It does **not** establish that any particular institution holds or operated that key.
Nothing below changes that, and no output of this feature says otherwise.

What the pilot format adds is *where the key material came from*: a small public-only bundle whose
exact bytes were authenticated by a SHA-256 digest the verifier's operator obtained **separately
from the receipts**. A digest shipped beside a receipt is not an independent decision.

## The format

One JSON object, canonical (RFC 8785) bytes, closed member set:

| Member | Meaning |
|---|---|
| `bundle_format` | the constant `arcs.pilot_trust_bundle.v0.1` |
| `bundle_version` | the publisher's own version string |
| `issuers[]` | one entry per signing key |

Each `issuers[]` entry: `issuer_id`, `key_id`, `algorithm` (`Ed25519`), `public_key` (canonical
unpadded base64url of the 32 raw bytes), `not_before`, `not_after` (RFC 3339 UTC, `...Z`),
`status` (`active` or `withdrawn`), `withdrawn_at` (only when withdrawn), and `signer_metadata`
(optional `service`, `custody`, `posture`, each short text). There is no field for private
material and no `trusted` flag: `active` plus an in-window `issued_at` is the whole of it. A
`key_id` appears once.

## Building a bundle (public keys only)

```bash
arcs-verify trust-bundle build --spec spec.json --out bundle.json
```

`spec.json` has `bundle_version` and `issuers[]`. `public_key` may be canonical base64url, a PEM
`PUBLIC KEY`, or a public JWK. The builder prints `trust_bundle_sha256`, the digest the owner then
distributes out of band. It refuses, writing nothing and echoing nothing of the input:

- any member that names private material (`private_key`, `seed`, `secret`, `d`, ...), at any depth;
- a PEM or OpenSSH private block, or in a text field an Ed25519 PKCS#8 key or a 32-byte seed followed by its own public key (base64, base64url or hex, at any character offset of the text so a glued label or suffix does not hide it, also split into groups joined by blanks, colons, dots, commas, semicolons, pipes, a literal `\n` or slashes; slashes only when the key's own base64 holds none; hex also with dashes), or a private JWK;
- a known public demonstration key (unless `--allow-known-test-keys`, for test bundles only);
- anything outside the closed shape, a duplicate `key_id`, an inverted window, a point that is not a
  prime-order Ed25519 key.

A raw 32-byte value cannot be told apart from a public key by its bytes. The builder takes *public*
keys by contract; it detects the private encodings that can be detected and says so.

## Verifying under a pinned bundle

```bash
arcs-verify receipt.json --trust-bundle bundle.json --trust-bundle-sha256 <digest from the owner>
```

The digest is checked **before** the bytes are parsed. A missing file, a missing or malformed pin, a
digest mismatch (a substituted or altered bundle) or a malformed bundle all leave the receipt judged
against a keyring that resolves nothing, with a named failure code and exit 1
(the code is printed by the CLI and appears under `failure_codes` in `--json`). A key whose `issued_at` falls outside its window, or
that is `withdrawn`, earns no `issuer_key_trusted`. A withdrawn key earns none for any receipt,
because `issued_at` is the signer's own assertion. The window is judged at `issued_at`, not at the
verification time.

## Trust policy (opt-in; the default is unchanged)

`--trust-policy default|flag|strict`. Without the flag, and without `--trust-bundle`, every
verification run (stdout, stderr and exit status, text and `--json`) is what it was before this
feature. The one visible difference for existing users is the `--help` and usage text, which
lists the three trust flags.

- `flag`: recognises known public demonstration keys by the SHA-256 fingerprint of the raw public
  key and reports them (`known_public_test_key` in `--json`, a `FLAG` line in text). The verdict is
  unchanged.
- `strict`: additionally clears `issuer_key_trusted` (code `known_public_test_key`) for such a key,
  and, for `--keyring`, when the keyring file is inside the receipt's directory tree or the receipt
  is inside the keyring's, after symlink resolution (code `keyring_co_located_with_receipt`). A
  keyring supplied by whoever supplied the receipts is not independent trust. Directories are
  compared by filesystem identity (`samefile`), for the path as given and as symlink-resolved, so
  letter case on a case-insensitive filesystem and symlinks do not hide co-location. A keyring
  with a duplicated `key_id` is refused as ambiguous, and every duplicate is checked against the
  known-key registry. A digest-pinned
  `--trust-bundle` is exempt from the location test: the out-of-band digest is what authenticates it.
  Strict never rewrites `signature_valid`.

Recognising a known test key means "its private half is published test material". It never means a
signer is genuine, and failing to recognise a key means nothing about the signer either.

## Limits

- Key windows are judged at the receipt's own `issued_at`, which is the signer's assertion. A key
  whose window has since closed is therefore still accepted for a receipt that claims an in-window
  `issued_at`; the report says so (`key_window_ended_before_verification`) but does not change the
  verdict. Withdrawal, not expiry, is the control for a compromised key.
- `key_window_ended_before_verification` depends on the date the verifier runs, so `--json` output for a bundle whose window has closed differs by run date. It never affects the verdict.
- Only key armour (a dashed `-----BEGIN ... PRIVATE KEY-----` line) is matched as text, so custody wording such as "private key held in an HSM" or "begin private key rotation" is fine. The armour match accepts two or more dashes, so a prose double dash directly before "begin private key" is refused too (the guard fails closed).
- The builder's text-field scan is a best-effort guard, not a proof. It refuses PEM/OpenSSH armour
  lines (also with invisible, full-width or Unicode-dash characters) and runs that actually parse as
  an **Ed25519** PKCS#8 key or as a seed plus its own public key. It does not detect other key types,
  base64 groups joined by `-` or `_`, pieces separated by labels, base64 pieces split by quotes, brackets, `=` or `*`, `0x`-prefixed hex byte lists, base32 and base85, or a key at a byte offset inside a larger base64 blob that is not a multiple of three bytes (for example the body of an unarmoured OpenSSH key; the armoured form is refused). It does not detect an Ed25519 PKCS#8 v2 key that embeds its public key either. A bare 32-byte
  seed, in a text field or as a `public_key`, cannot be told apart from a public value or a digest by
  its bytes and is not detected. The real control is that the builder takes public keys by contract
  and the owner reviews a bundle before publishing it. Scan cost is negligible for ordinary fields; a
  field of 200 base64 characters costs about 20 ms, and any text value over 512 characters is refused
  unscanned. The `public_key` field is not covered by that cap: its armour match runs on any length, and a very long run of dashes is slow (about 19 s at 40,000 characters), a cost to the builder and, after the pin has matched, to the verifier's pinned-bundle loader.
- The registry of known public test keys is a fixed list of the demonstration and fixture keys this
  repository and other public proof sets publish. It is not a revocation service and is not
  complete.
- Co-location is a location test. It cannot know whether two directories are controlled by the same
  party. Strict is a floor, not a proof of independence.
- Nothing here issues, rotates, generates or publishes a key or a bundle. Those are owner acts.

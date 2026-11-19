"""Re-check the chat-integrations receipt evidence with ARCS Verify only.

Usage: python check.py [path/to/arcs-verify]

For each part (record-level, source-level) this reads the trust bundle, checks
it against the SHA-256 pin in out-of-band/, then runs the verifier under the
strict trust policy on every file:

- receipts/*.json must pass (exit 0);
- mutated/*.json must fail (exit 1) with failure code signature_invalid.

It imports no producer code and uses only the Python standard library and the
arcs-verify command. It prints one line per file and exits 0 only if every
expectation holds.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFY = sys.argv[1] if len(sys.argv) > 1 else "arcs-verify"


def profile_of(receipt: Path) -> str:
    data = json.loads(receipt.read_bytes())
    return f"{data['profile_id']}.{data['profile_version']}"


def run(receipt: Path, bundle: Path, pin: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [VERIFY, str(receipt), "--trust-bundle", str(bundle), "--trust-bundle-sha256", pin,
         "--trust-policy", "strict", "--profile", profile_of(receipt), "--json"],
        capture_output=True, text=True,
    )
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        report = {}
    return proc.returncode, report


def main() -> int:
    ok = True
    checked = 0
    for part in ("record-level", "source-level"):
        base = HERE / part
        bundle = base / "trust" / "trust-bundle.json"
        pin = (base / "out-of-band" / "trust-bundle.sha256").read_text().strip()
        actual = hashlib.sha256(bundle.read_bytes()).hexdigest()
        if actual != pin:
            print(f"FAIL {part}: trust bundle SHA-256 {actual} != pin {pin}")
            ok = False
            continue
        for receipt in sorted((base / "receipts").glob("*.json")):
            code, report = run(receipt, bundle, pin)
            good = code == 0 and report.get("passed") is True
            print(f"{'PASS' if good else 'FAIL'} {part}/receipts/{receipt.name}: exit {code}, expected 0")
            ok &= good
            checked += 1
        for receipt in sorted((base / "mutated").glob("*.json")):
            code, report = run(receipt, bundle, pin)
            codes = report.get("failure_codes", [])
            good = code == 1 and "signature_invalid" in codes
            print(f"{'PASS' if good else 'FAIL'} {part}/mutated/{receipt.name}: exit {code} {codes}, expected 1 signature_invalid")
            ok &= good
            checked += 1
    print(f"{checked} files checked; {'all expectations held' if ok and checked else 'SOME EXPECTATIONS FAILED'}")
    return 0 if ok and checked else 1


if __name__ == "__main__":
    raise SystemExit(main())

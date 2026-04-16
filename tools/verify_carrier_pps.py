#!/usr/bin/env python3
"""PPS-aligned carrier verifier.

Aligns carrier hashing & signature verification with Prophet Protocol Spec (PPS):
- Canonical bytes: RFC 8785 JSON Canonicalization Scheme (JCS)
- Hash: BLAKE3-256
- Signature: Ed25519 over the 32-byte BLAKE3 digest of the canonical CarrierBody

CarrierBody in this repo's emitted JSON is:
  {"type": ..., "time": ..., "payload": ..., "dryRun": ...}
Signature fields live alongside:
  "sig" (hex), "pub" (hex)

Usage:
  python3 tools/verify_carrier_pps.py [out/carriers]
"""

from __future__ import annotations

import argparse
import binascii
import json
import os
import sys
from typing import Any, Dict

from blake3 import blake3
import jcs
from nacl.signing import VerifyKey


def _jcs_bytes(obj: Any) -> bytes:
    if hasattr(jcs, "canonicalize"):
        out = jcs.canonicalize(obj)
        return out if isinstance(out, (bytes, bytearray)) else str(out).encode("utf-8")
    if hasattr(jcs, "dumps"):
        out = jcs.dumps(obj)
        return out.encode("utf-8") if isinstance(out, str) else bytes(out)
    raise RuntimeError("Unsupported jcs API; expected canonicalize() or dumps().")


def _carrier_body(o: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": o["type"],
        "time": o["time"],
        "payload": o["payload"],
        "dryRun": o["dryRun"],
    }


def verify_file(path: str) -> bool:
    o = json.load(open(path, "r", encoding="utf-8"))
    canon = _jcs_bytes(_carrier_body(o))
    digest = blake3(canon).digest()
    sig = binascii.unhexlify(o["sig"])
    pub = binascii.unhexlify(o["pub"])
    VerifyKey(pub).verify(digest, sig)
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="out/carriers", help="Directory or single carrier JSON file")
    args = ap.parse_args()

    target = args.path
    ok = 0
    fail = 0

    if os.path.isfile(target) and target.endswith(".json"):
        try:
            verify_file(target)
            ok += 1
        except Exception:
            fail += 1
    elif os.path.isdir(target):
        for name in sorted(os.listdir(target)):
            if not name.endswith(".json"):
                continue
            fp = os.path.join(target, name)
            try:
                verify_file(fp)
                ok += 1
            except Exception:
                fail += 1
    else:
        if target == "out/carriers":
            print(json.dumps({"verified": ok, "failed": fail}))
            return 0
        print(json.dumps({"error": f"path not found: {target}"}), file=sys.stderr)
        return 2

    print(json.dumps({"verified": ok, "failed": fail}))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

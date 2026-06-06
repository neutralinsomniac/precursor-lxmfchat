#!/usr/bin/env python3
"""LXMF reference oracle for Rust interop.

  lxmfref.py pack  <src_prv_hex> <dst_prv_hex> <title> <content>
      -> prints packed LXMF bytes (hex) and message hash
  lxmfref.py parse <packed_hex> <src_pub_hex>
      -> unpacks via the LXMF library, prints content/title and signature validity
"""
import os
import sys
import tempfile
import RNS
import LXMF

_R = None


def init():
    global _R
    if _R is None:
        d = tempfile.mkdtemp(prefix="lxmfref-")
        with open(os.path.join(d, "config"), "w") as f:
            f.write("[reticulum]\n  enable_transport = No\n  share_instance = No\n"
                    "  panic_on_interface_error = No\n[logging]\n  loglevel = 1\n[interfaces]\n")
        _R = RNS.Reticulum(configdir=d)
    return _R


def identity(prv_hex):
    idn = RNS.Identity(create_keys=False)
    idn.load_private_key(bytes.fromhex(prv_hex))
    return idn


def main():
    cmd = sys.argv[1]
    init()
    if cmd == "pack":
        src = identity(sys.argv[2])
        dst = identity(sys.argv[3])
        title, content = sys.argv[4], sys.argv[5]
        src_dest = RNS.Destination(src, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
        dst_dest = RNS.Destination(dst, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
        msg = LXMF.LXMessage(dst_dest, src_dest, content, title, desired_method=LXMF.LXMessage.OPPORTUNISTIC)
        # Fixed timestamp for reproducible known-answer vectors (override time.time()).
        if len(sys.argv) > 6 and sys.argv[6]:
            msg.timestamp = float(sys.argv[6])
        msg.pack()
        print("packed", msg.packed.hex())
        print("hash", msg.hash.hex())
    elif cmd == "parse":
        packed = bytes.fromhex(sys.argv[2])
        src_pub = bytes.fromhex(sys.argv[3])
        source_hash = packed[16:32]
        # Teach RNS the source identity so unpack_from_bytes can recall + verify it.
        src_id = RNS.Identity(create_keys=False)
        src_id.load_public_key(src_pub)
        RNS.Identity.remember(None, source_hash, src_pub, None)
        msg = LXMF.LXMessage.unpack_from_bytes(packed)
        print("title", msg.title_as_string())
        print("content", msg.content_as_string())
        print("valid", bool(msg.signature_validated))
    else:
        raise SystemExit("unknown command")


if __name__ == "__main__":
    main()

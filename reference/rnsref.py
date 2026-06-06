#!/usr/bin/env python3
"""Reference oracle: deterministic RNS values + encrypt/decrypt, for Rust interop.

Usage:
  rnsref.py dump <prv_hex(128)>
      -> prints identity hash, public_key, lxmf.delivery destination hash
  rnsref.py decrypt <prv_hex> <token_hex>
      -> decrypts a token (produced by our Rust code) and prints plaintext hex
  rnsref.py encrypt <prv_hex> <plaintext_hex>
      -> encrypts to the identity, prints the token hex (for Rust to decrypt)
"""
import os
import sys
import tempfile
import RNS

_RETICULUM = None


def init_reticulum():
    """Spin up a headless Reticulum instance with no interfaces (no network)."""
    global _RETICULUM
    if _RETICULUM is not None:
        return _RETICULUM
    cfgdir = tempfile.mkdtemp(prefix="rnsref-")
    with open(os.path.join(cfgdir, "config"), "w") as f:
        f.write("[reticulum]\n  enable_transport = No\n  share_instance = No\n  panic_on_interface_error = No\n\n[logging]\n  loglevel = 1\n\n[interfaces]\n")
    _RETICULUM = RNS.Reticulum(configdir=cfgdir)
    return _RETICULUM


def load(prv_hex):
    idn = RNS.Identity(create_keys=False)
    idn.load_private_key(bytes.fromhex(prv_hex))
    return idn


def main():
    cmd = sys.argv[1]
    if cmd == "valann":
        init_reticulum()
        raw = bytes.fromhex(sys.argv[2])
        pkt = make_inbound(raw)
        ok = RNS.Identity.validate_announce(pkt, only_validate_signature=False)
        print("valid", bool(ok))
        return
    idn = load(sys.argv[2])
    if cmd == "dump":
        dest = RNS.Destination(idn, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
        print("identity_hash", idn.hash.hex())
        print("public_key", idn.get_public_key().hex())
        print("name_hash", RNS.Destination.full_name_hash("lxmf", "delivery").hex()
              if hasattr(RNS.Destination, "full_name_hash") else "n/a")
        print("dest_hash", dest.hash.hex())
    elif cmd == "decrypt":
        token = bytes.fromhex(sys.argv[3])
        pt = idn.decrypt(token)
        print("plaintext", pt.hex() if pt is not None else "DECRYPT_FAILED")
    elif cmd == "encrypt":
        pt = bytes.fromhex(sys.argv[3])
        token = idn.encrypt(pt)
        print("token", token.hex())
    elif cmd == "announce":
        # build an announce packet for lxmf.delivery (no ratchets) and dump raw
        init_reticulum()
        app_data = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None
        dest = RNS.Destination(idn, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
        pkt = dest.announce(app_data=app_data, send=False)
        pkt.pack()
        print("raw", pkt.raw.hex())
    else:
        raise SystemExit("unknown command")


class FakePacket:
    """Minimal packet shim with the attributes validate_announce needs."""
    def get_hash(self):
        return RNS.Identity.full_hash(bytes([self.flags & 0x0F]) + self.raw[2:])


def make_inbound(raw):
    p = FakePacket()
    p.raw = raw
    p.flags = raw[0]
    p.hops = raw[1]
    p.header_type = (p.flags & 0b01000000) >> 6
    p.context_flag = (p.flags & 0b00100000) >> 5
    p.transport_type = (p.flags & 0b00010000) >> 4
    p.destination_type = (p.flags & 0b00001100) >> 2
    p.packet_type = p.flags & 0b00000011
    dl = RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    p.transport_id = None
    p.destination_hash = raw[2:dl + 2]
    p.context = raw[dl + 2]
    p.data = raw[dl + 3:]
    p.rssi = None
    p.snr = None
    return p


if __name__ == "__main__":
    main()

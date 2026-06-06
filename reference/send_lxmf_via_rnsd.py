#!/usr/bin/env python3
"""Connect to the local rnsd hub over TCP, learn the Rust client's address from
its announce, and send it an opportunistic LXMF message. Also announces our own
(sender) destination so the receiver can verify our signature.

  send_lxmf_via_rnsd.py <recipient_dest_hash_hex> <text>
"""
import os
import sys
import time
import tempfile
import RNS
import LXMF


def main():
    recipient_hash = bytes.fromhex(sys.argv[1])
    text = sys.argv[2]

    cfgdir = tempfile.mkdtemp(prefix="lxmf-sender-")
    with open(os.path.join(cfgdir, "config"), "w") as f:
        f.write(
            "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
            "  panic_on_interface_error = No\n[logging]\n  loglevel = 3\n[interfaces]\n"
            "  [[hub]]\n    type = TCPClientInterface\n    enabled = Yes\n"
            "    target_host = 127.0.0.1\n    target_port = 4242\n"
        )
    RNS.Reticulum(configdir=cfgdir)

    # Sender identity (0x07*32 / 0x08*32) and its lxmf.delivery destination.
    sender = RNS.Identity(create_keys=False)
    sender.load_private_key(bytes.fromhex(("07" * 32) + ("08" * 32)))
    src_dest = RNS.Destination(sender, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
    src_dest.announce()
    print("sender announced", src_dest.hash.hex())

    # Wait until we learn the recipient's identity from its announce.
    print("waiting to learn recipient", recipient_hash.hex())
    deadline = time.time() + 30
    recalled = None
    while time.time() < deadline:
        recalled = RNS.Identity.recall(recipient_hash)
        if recalled is not None:
            break
        time.sleep(0.5)
    if recalled is None:
        print("FAIL: never learned recipient identity")
        sys.exit(1)
    print("learned recipient identity; sending")

    dst_dest = RNS.Destination(recalled, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
    msg = LXMF.LXMessage(dst_dest, src_dest, text, "", desired_method=LXMF.LXMessage.OPPORTUNISTIC)
    msg.pack()
    pkt = RNS.Packet(dst_dest, msg.packed[LXMF.LXMessage.DESTINATION_LENGTH:])
    pkt.send()
    print("sent opportunistic LXMF:", text)
    time.sleep(3)  # allow delivery


if __name__ == "__main__":
    main()

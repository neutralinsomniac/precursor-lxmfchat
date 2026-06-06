#!/usr/bin/env python3
"""Send a DIRECT (link) LXMF message via a real LXMRouter over the local rnsd,
with verbose RNS logging so link establishment/teardown reasons are visible.

  send_direct_via_rnsd.py <recipient_dest_hash_hex> <text>
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

    cfgdir = tempfile.mkdtemp(prefix="lxmf-direct-")
    with open(os.path.join(cfgdir, "config"), "w") as f:
        f.write(
            "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
            "  panic_on_interface_error = No\n[logging]\n  loglevel = 7\n[interfaces]\n"
            "  [[hub]]\n    type = TCPClientInterface\n    enabled = Yes\n"
            "    target_host = 127.0.0.1\n    target_port = 4242\n"
        )
    RNS.Reticulum(configdir=cfgdir)

    router = LXMF.LXMRouter(storagepath=os.path.join(cfgdir, "lxmf"))
    sender_identity = RNS.Identity(create_keys=False)
    sender_identity.load_private_key(bytes.fromhex(("07" * 32) + ("08" * 32)))
    source_dest = router.register_delivery_identity(sender_identity, display_name="direct-sender")
    router.announce(source_dest.hash)
    print("sender announced", source_dest.hash.hex())

    print("waiting to learn recipient", recipient_hash.hex())
    deadline = time.time() + 30
    recalled = None
    asked = 0
    while time.time() < deadline:
        recalled = RNS.Identity.recall(recipient_hash)
        if recalled is not None:
            break
        if asked % 6 == 0:  # nudge the network for the path every ~3s
            RNS.Transport.request_path(recipient_hash)
        asked += 1
        time.sleep(0.5)
    if recalled is None:
        print("FAIL: never learned recipient identity")
        sys.exit(1)

    dest = RNS.Destination(recalled, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
    msg = LXMF.LXMessage(dest, source_dest, text, "", desired_method=LXMF.LXMessage.DIRECT)

    def delivered(m):
        print("=== DELIVERED:", text)

    def failed(m):
        print("=== FAILED to deliver:", text)

    msg.register_delivery_callback(delivered)
    msg.register_failed_callback(failed)
    router.handle_outbound(msg)
    print("handed outbound DIRECT message to router; observing for 40s...")
    time.sleep(40)


if __name__ == "__main__":
    main()

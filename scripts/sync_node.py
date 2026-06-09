#!/usr/bin/env python3
"""Minimal **real-RNS** LXMF propagation node, for validating the Precursor's
message-sync client (host-client `sync` mode) on the wire.

It stands up a Reticulum TCPServerInterface, owns an `lxmf.propagation`
destination with a "/get" request handler that speaks the LXMF message-sync
protocol, and serves ONE test message (built byte-for-byte like our
`lxmf::message::pack`, then encrypted to the requesting client) so the client can
download, decrypt, verify, and delete it. Uses real `rns` for the link, request/
response, and Resource transfer — so it exercises our Resource *receiver* against
genuine RNS sending.

  scripts/sync_node.py            # listens on 127.0.0.1:4250, prints the
                                  # propagation dest hash to give host-client
"""
import os
import sys
import time
import tempfile

import RNS
from RNS.vendor import umsgpack

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 4250

# Fixed identities so addresses are stable across runs.
NODE_SEED = bytes.fromhex(("a1" * 32) + ("a2" * 32))
SENDER_SEED = bytes.fromhex(("b1" * 32) + ("b2" * 32))

# Large enough that the /get message response exceeds the link MDU and RNS sends
# it as a multi-part Resource (exercising our Resource receiver), not a packet.
CONTENT = b"propagation node sync test - " + (b"the quick brown fox jumps over the lazy dog. " * 80)
TITLE = b"synctest"


def build_lxmf_data(recipient_identity, sender_identity, sender_dest):
    """`dest_hash(16) || encrypt_to_recipient(source||sig||payload)`, matching our
    `pack()` (message_id = full_hash(dest+source+payload); sig over +message_id)."""
    r_dest = RNS.Destination(recipient_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
    payload = umsgpack.packb([time.time(), TITLE, CONTENT, {}])
    hashed = r_dest.hash + sender_dest.hash + payload
    message_id = RNS.Identity.full_hash(hashed)
    signature = sender_identity.sign(hashed + message_id)
    packed = r_dest.hash + sender_dest.hash + signature + payload
    plaintext = packed[16:]  # source || sig || payload (the opportunistic plaintext)
    ciphertext = r_dest.encrypt(plaintext)
    return r_dest.hash + ciphertext


def main():
    cfgdir = tempfile.mkdtemp(prefix="sync-node-")
    with open(os.path.join(cfgdir, "config"), "w") as f:
        f.write(
            "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
            "  panic_on_interface_error = No\n[logging]\n  loglevel = 4\n[interfaces]\n"
            "  [[server]]\n    type = TCPServerInterface\n    enabled = Yes\n"
            f"    listen_ip = {LISTEN_IP}\n    listen_port = {LISTEN_PORT}\n"
        )
    RNS.Reticulum(configdir=cfgdir)

    node_identity = RNS.Identity(create_keys=False)
    node_identity.load_private_key(NODE_SEED)
    sender_identity = RNS.Identity(create_keys=False)
    sender_identity.load_private_key(SENDER_SEED)

    prop_dest = RNS.Destination(node_identity, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "propagation")
    prop_dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
    sender_dest = RNS.Destination(sender_identity, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
    sender_dest.set_proof_strategy(RNS.Destination.PROVE_ALL)

    # transient_id -> lxmf_data, built per-recipient on first contact.
    store = {}
    built_for = {}

    def get_handler(path, data, request_id, link_id, remote_identity, requested_at):
        if remote_identity is None:
            print("  /get from unidentified peer -> ERROR_NO_IDENTITY (240)")
            return 240
        rid = remote_identity.hash
        if rid not in built_for:
            lxmf_data = build_lxmf_data(remote_identity, sender_identity, sender_dest)
            tid = RNS.Identity.full_hash(lxmf_data)
            store[tid] = lxmf_data
            built_for[rid] = tid
            print(f"  built test message for {RNS.prettyhexrep(rid)} tid={RNS.prettyhexrep(tid)}")

        want = data[0] if len(data) > 0 else None
        have = data[1] if len(data) > 1 else None
        if want is None and have is None:
            print("  /get [None,None] -> listing", len(store), "message(s)")
            return list(store.keys())
        if want is None and have is not None:
            for tid in have:
                store.pop(tid, None)
            print("  /get [None,haves] -> deleted", len(have), "message(s); store now", len(store))
            return []
        # want = list of transient ids
        msgs = [store[tid] for tid in want if tid in store]
        print("  /get [wants,...] -> returning", len(msgs), "message(s)")
        return msgs

    prop_dest.register_request_handler("/get", get_handler, allow=RNS.Destination.ALLOW_ALL)

    print("propagation dest:", prop_dest.hash.hex())
    print("sender dest:      ", sender_dest.hash.hex())
    print(f"listening on {LISTEN_IP}:{LISTEN_PORT}; announcing every 5s. Ctrl-C to stop.")
    try:
        while True:
            # Announce the sender first so a client learns it before syncing and
            # can verify the message signature.
            sender_dest.announce()
            time.sleep(1)
            prop_dest.announce()
            time.sleep(4)
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()

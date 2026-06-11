#!/usr/bin/env python3
"""Minimal **real-RNS** NomadNet-style page node, for validating the Precursor's
page-browser client (host-client `fetch` mode) on the wire.

It stands up a Reticulum TCPServerInterface and a `nomadnetwork.node`
destination (announced with the node name as raw utf-8 app_data, like real
NomadNet), and serves micron pages through RNS request handlers registered
with ALLOW_ALL — so anonymous (non-identified) requests work, exactly like
NomadNet's Node.serve_page. A large page forces the response down the RNS
Resource path, exercising our Resource receiver.

  scripts/page_node.py            # listens on 127.0.0.1:4251, prints the
                                  # node dest hash to give host-client
  PAGE_NODE_HUB=host:port scripts/page_node.py
                                  # instead JOIN a real hub as a client, so a
                                  # device on that hub can browse this node
                                  # across the real network
"""
import os
import tempfile
import time

import RNS

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 4251
HUB = os.environ.get("PAGE_NODE_HUB")  # "host:port" → TCPClientInterface mode

# Fixed identity so the node address is stable across runs.
NODE_SEED = bytes.fromhex(("c1" * 32) + ("c2" * 32))
NODE_NAME = "pagetest node"

OTHER_HASH = "00112233445566778899aabbccddeeff"

INDEX_PAGE = f"""#!c=300
# comment line, must not render
>Test Node
Welcome to the `!page test`! node.
-
`cCentered line
`=
literal `! block [no`link]
`=
Links: [Other page`:/page/other.mu] and [{OTHER_HASH}:/page/remote.mu]
Bare node [{OTHER_HASH}] and address [operator`lxmf@{OTHER_HASH}]
"""

OTHER_PAGE = """>Other Page
You followed a link. [Back to index`:/page/index.mu]
"""

# Big enough that the response exceeds the link MDU and real RNS sends it as a
# multi-part Resource. PAGE_TEST_REPEAT=2000 makes it span multiple hashmap
# pages (HMU round-trips).
BIG_PAGE = ">Big Page\n" + (
    "`!filler`! line with a [link`:/page/index.mu] and text padding it out\n"
    * int(os.environ.get("PAGE_TEST_REPEAT", "400"))
)


def main():
    cfgdir = tempfile.mkdtemp(prefix="page-node-")
    if HUB:
        host, port = HUB.rsplit(":", 1)
        iface = (
            "  [[hub]]\n    type = TCPClientInterface\n    enabled = Yes\n"
            f"    target_host = {host}\n    target_port = {port}\n"
        )
    else:
        iface = (
            "  [[server]]\n    type = TCPServerInterface\n    enabled = Yes\n"
            f"    listen_ip = {LISTEN_IP}\n    listen_port = {LISTEN_PORT}\n"
        )
    with open(os.path.join(cfgdir, "config"), "w") as f:
        f.write(
            "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
            "  panic_on_interface_error = No\n[logging]\n  loglevel = 4\n[interfaces]\n" + iface
        )
    RNS.Reticulum(configdir=cfgdir)

    node_identity = RNS.Identity(create_keys=False)
    node_identity.load_private_key(NODE_SEED)

    node_dest = RNS.Destination(
        node_identity, RNS.Destination.IN, RNS.Destination.SINGLE, "nomadnetwork", "node"
    )

    def page_handler(page):
        # NomadNet's serve_page returns the page file's content; identity is
        # optional (handlers are ALLOW_ALL) and may be None for anonymous
        # requests — exactly what the Precursor browser sends.
        def handler(path, data, request_id, link_id, remote_identity, requested_at):
            who = "anonymous" if remote_identity is None else RNS.prettyhexrep(remote_identity.hash)
            print(f"  served {path} to {who} ({len(page)} bytes)")
            return page

        return handler

    # One served as str, one as bytes: RNS packs these differently (msgpack
    # str vs bin) and the client must handle both.
    node_dest.register_request_handler(
        "/page/index.mu", response_generator=page_handler(INDEX_PAGE), allow=RNS.Destination.ALLOW_ALL
    )
    node_dest.register_request_handler(
        "/page/other.mu",
        response_generator=page_handler(OTHER_PAGE.encode("utf-8")),
        allow=RNS.Destination.ALLOW_ALL,
    )
    node_dest.register_request_handler(
        "/page/big.mu", response_generator=page_handler(BIG_PAGE), allow=RNS.Destination.ALLOW_ALL
    )

    print("node dest:", node_dest.hash.hex())
    print(f"listening on {LISTEN_IP}:{LISTEN_PORT}; announcing every 5s. Ctrl-C to stop.")
    try:
        while True:
            # Raw utf-8 name as app_data, like NomadNet Node.announce.
            node_dest.announce(app_data=NODE_NAME.encode("utf-8"))
            time.sleep(5)
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()

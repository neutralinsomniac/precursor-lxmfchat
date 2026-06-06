#!/usr/bin/env python3
"""Replicate RNS initiator's Link.validate_proof to check our responder's proof.

  validate_link_proof.py <our_pubkey_hex> <request_raw_hex> <link_id_hex> <proof_raw_hex>
"""
import sys
import RNS

ECPUBSIZE = 64
SIGLEN = 64
LINK_MTU_SIZE = 3
MTU_BYTEMASK = 0x1FFFFF


def get_hashable_part(raw):
    hp = bytes([raw[0] & 0x0F])
    header_type = (raw[0] & 0b01000000) >> 6
    if header_type == 1:  # HEADER_2
        hp += raw[(128 // 8) + 2:]
    else:
        hp += raw[2:]
    return hp


def link_id_from_request(raw):
    hp = get_hashable_part(raw)
    # data starts after flags(1)+hops(1)+dest(16)+context(1) = 19 for HEADER_1
    data = raw[19:]
    if len(data) > ECPUBSIZE:
        diff = len(data) - ECPUBSIZE
        hp = hp[:-diff]
    return RNS.Identity.truncated_hash(hp)


def main():
    our_pub = bytes.fromhex(sys.argv[1])
    request_raw = bytes.fromhex(sys.argv[2])
    given_link_id = bytes.fromhex(sys.argv[3])
    proof_raw = bytes.fromhex(sys.argv[4])

    # recompute link id from the request the RNS way
    link_id = link_id_from_request(request_raw)
    print("link_id match:", link_id == given_link_id, link_id.hex())

    # proof packet is HEADER_1: data starts at offset 19
    proof_data = proof_raw[19:]
    print("proof_data len:", len(proof_data), "(expect 99 = 64 sig + 32 pub + 3 signalling)")

    mode = proof_data[ECPUBSIZE + SIGLEN - 64 + 96 - 96] if False else (proof_data[96] >> 5)
    signalling = proof_data[96:99]
    peer_pub = proof_data[SIGLEN:SIGLEN + 32]
    peer_sig_pub = our_pub[32:64]
    signed = link_id + peer_pub + peer_sig_pub + signalling
    signature = proof_data[:SIGLEN]

    idn = RNS.Identity(create_keys=False)
    idn.load_public_key(our_pub)
    valid = idn.validate(signature, signed)
    print("mode:", mode, "(expect 1 = AES256)")
    print("signature valid:", bool(valid))


if __name__ == "__main__":
    main()

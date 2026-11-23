"""Drives the applet's TSW commands: K leaves, host-built tree, one signature, checked
against tsw_ref and timed.

    python tsw_run.py [--set w256|w16] [--keys 4] [--leaf I] [--host-rho] [--sim]
"""

import argparse
import os

import tsw_ref as ref
from run import Card

SET_P1 = {"w256": 0, "w16": 1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default="w256", choices=list(SET_P1))
    ap.add_argument("--keys", type=int, default=4, choices=[1, 2, 4, 8])
    ap.add_argument("--leaf", type=int, default=0)
    ap.add_argument("--secret", default="07" * 32)
    ap.add_argument("--nonce", type=int, default=0)
    ap.add_argument("--message", default=None, help="32-byte message, hex (random if omitted)")
    ap.add_argument("--host-rho", action="store_true", help="grind rho on the host; the card checks the sum")
    ap.add_argument("--sim", action="store_true")
    a = ap.parse_args()
    if a.leaf >= a.keys:
        raise SystemExit("--leaf must be below --keys")

    secret = bytes.fromhex(a.secret)
    msg = bytes.fromhex(a.message) if a.message else os.urandom(32)
    s = ref.Tsw(a.set)
    sk, p = ref.tree_seeds(secret, a.nonce)
    card = Card(sim=a.sim)

    card.cmd(0x10, data=secret)
    p_card, dt = card.cmd(0x50, SET_P1[a.set], 0, a.nonce.to_bytes(16, "little"), le=16)
    assert p_card == p, "P differs from the reference"
    print(f"TSW {a.set} ({s.v} chains, T = {s.t}), K = {a.keys}, nonce {a.nonce}: derive seeds {dt * 1e3:.1f} ms")

    leaves, total = [], 0.0
    for e in range(a.keys):
        leaf, dt = card.cmd(0x52, e, le=16)
        assert leaf == s.leaf(sk, p, e), f"leaf {e} differs from the reference"
        leaves.append(leaf)
        total += dt
        print(f"leaf {e}: {dt * 1e3:9.1f} ms  {leaf.hex()}")
    print(f"{a.keys} leaves: {total:.2f} s total, {total / a.keys * 1e3:.1f} ms mean")

    root, paths = s.merkle(p, leaves)
    rho_ref, codeword, tries_ref = s.grind(sk, p, a.leaf, msg)
    if a.host_rho:
        # Any rho that hits the target works; grinding needs only public data (P, epoch, M).
        ctr = 0
        while True:
            rho = os.urandom(16)
            ctr += 1
            if s.encode(p, rho, a.leaf, msg) is not None:
                break
        data, expect = msg + rho, s.ots_sign(sk, p, a.leaf, msg, rho)[0]
        how = f"host-ground rho ({ctr} host tries)"
    else:
        data, expect = msg, s.ots_sign(sk, p, a.leaf, msg)[0]
        how = f"card-ground rho, expected {tries_ref} tries"
    resp, t_sign = card.cmd(0x54, a.leaf, 0, data, le=2)
    tries = int.from_bytes(resp, "big")
    out, t_read = b"", 0.0
    while len(out) < ref.N + s.v * ref.N:
        chunk, dt = card.cmd(0x32, len(out) >> 8, len(out) & 0xFF, le=0)
        out += chunk
        t_read += dt
    assert out == expect, "signature differs from the reference"
    sig = bytes([a.leaf]) + out + paths[a.leaf]
    assert s.tree_verify(p, root, a.keys, msg, sig), "signature does not verify"
    chain_steps = sum(s.encode(p, out[:16], a.leaf, msg))
    print(f"\nsign leaf {a.leaf}: {t_sign * 1e3:.1f} ms, {how}; card tries {tries}, "
          f"{chain_steps} chain steps (+ {t_read * 1e3:.1f} ms to read {len(out)} B)")
    print(f"public key {(p + root).hex()}")
    print(f"{len(sig)}-byte signature matches the reference and verifies")


if __name__ == "__main__":
    main()

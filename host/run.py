"""Drives WotsApplet on a card: checks every result against wots_ref and times each step.

    python run.py [--secret HEX32] [--nonce N] [--leaf I] [--bench COUNT]

Leaves come from the card one at a time; the host builds the Merkle tree, has the card sign a
32-byte message with one leaf, assembles PR 1088's 625-byte auth data and verifies it.
"""

import argparse
import os
import time

import pcsc
import subprocess
from pathlib import Path


class SimReader:
    """jCardSim through sim/run-sim.sh, same interface as pcsc.Reader."""

    def __init__(self):
        script = Path(__file__).resolve().parent.parent / "sim" / "run-sim.sh"
        self.p = subprocess.Popen([str(script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def transmit(self, apdu):
        self.p.stdin.write(apdu.hex() + "\n")
        self.p.stdin.flush()
        out = bytes.fromhex(self.p.stdout.readline().strip())
        return out[:-2], out[-2], out[-1]

import wots_ref as ref

AID = bytes.fromhex("F04C4545574F545301")
CLA = 0x80


class Card:
    def __init__(self, sim=False):
        self.conn = SimReader() if sim else pcsc.Reader()
        self.send(0x00, 0xA4, 0x04, 0x00, AID)

    def send(self, cla, ins, p1=0, p2=0, data=b"", le=None):
        apdu = [cla, ins, p1, p2]
        if data:
            apdu += [len(data)] + list(data)
        if le is not None:
            apdu += [le]
        t = time.perf_counter()
        resp, sw1, sw2 = self.conn.transmit(bytes(apdu))
        dt = time.perf_counter() - t
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(f"INS {ins:02X} failed: SW={sw1:02X}{sw2:02X}")
        return bytes(resp), dt

    def cmd(self, ins, p1=0, p2=0, data=b"", le=None):
        return self.send(CLA, ins, p1, p2, data, le)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", default="07" * 32, help="32-byte PublicAccountSecret, hex")
    ap.add_argument("--nonce", type=int, default=0)
    ap.add_argument("--keys", type=int, default=8, choices=[1, 2, 4, 8], help="leaves per tree")
    ap.add_argument("--leaf", type=int, default=0)
    ap.add_argument("--message", default=None, help="32-byte message, hex (random if omitted)")
    ap.add_argument("--bench", type=int, default=200, help="hash calls per bench mode (0 = skip)")
    ap.add_argument("--sim", action="store_true", help="use jCardSim instead of the reader")
    a = ap.parse_args()

    secret = bytes.fromhex(a.secret)
    msg = bytes.fromhex(a.message) if a.message else os.urandom(32)
    card = Card(sim=a.sim)

    flags, _ = card.cmd(0x42, le=1)
    print(f"InitializedMessageDigest(SHA-256): {'yes' if flags[0] & 1 else 'no'}")

    if a.bench:
        count = a.bench.to_bytes(2, "big")
        base, _ = None, None
        for mode, label in [(0, "empty loop"), (1, "SHA-256, 55 B (1 block)"),
                            (2, "F, 102 B in place (2 blocks)"), (3, "T_len, 646 B (11 blocks)"),
                            (4, "F via midstate, 38 B (1 block)")]:
            if mode == 4 and not flags[0] & 1:
                continue
            _, dt = card.cmd(0x40, mode, 0, count)
            if mode == 0:
                base = dt
                print(f"bench {label:34s} {dt * 1e3:8.1f} ms total (APDU + loop overhead)")
            else:
                print(f"bench {label:34s} {(dt - base) / a.bench * 1e3:8.3f} ms per call")

    card.cmd(0x10, data=secret)
    pk_seed, dt = card.cmd(0x12, data=a.nonce.to_bytes(16, "little"), le=16)
    if a.leaf >= a.keys:
        raise SystemExit("--leaf must be below --keys")
    tree = ref.Tree(ref.key_seed(secret, a.nonce), keys=a.keys)
    assert pk_seed == tree.pk_seed, "PK.seed differs from the reference"
    print(f"\nnonce {a.nonce}: derive seeds {dt * 1e3:.1f} ms, PK.seed {pk_seed.hex()}")

    leaves, times = [], []
    for i in range(a.keys):
        leaf, dt = card.cmd(0x20, i, le=16)
        assert leaf == tree.leaves[i], f"leaf {i} differs from the reference"
        leaves.append(leaf)
        times.append(dt)
        print(f"leaf {i}: {dt * 1e3:8.1f} ms  {leaf.hex()}")
    print(f"{a.keys} leaves: {sum(times):.2f} s total, {sum(times) / a.keys * 1e3:.1f} ms mean")

    root, paths = ref.merkle(leaves, pk_seed)
    public_key = pk_seed + root
    _, t_sign = card.cmd(0x30, a.leaf, 0, root + msg)
    out, t_read = b"", 0.0
    while len(out) < ref.N + ref.LEN * ref.N:
        chunk, dt = card.cmd(0x32, len(out) >> 8, len(out) & 0xFF, le=0)
        out += chunk
        t_read += dt
    auth = ref.assemble(a.leaf, out, paths[a.leaf])
    assert auth == tree.sign(a.leaf, msg), "signature differs from the reference"
    assert ref.verify(public_key, msg, auth, keys=a.keys), "signature does not verify"
    print(f"\nsign leaf {a.leaf}: {t_sign * 1e3:.1f} ms (+ {t_read * 1e3:.1f} ms to read 576 B)")
    print(f"public key {public_key.hex()}")
    print(f"{len(auth)}-byte auth data matches the reference and verifies")


if __name__ == "__main__":
    main()

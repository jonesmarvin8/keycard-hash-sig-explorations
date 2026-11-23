"""Reference target-sum Winternitz (TSW) tree, ported from logos-execution-zone's
tools/hbs_bench/src/tsw.rs (commit b081a831d) at its "L1 attack" sizing: n = |P| = |rho| = 16.

Tweakable hash: Th(parts) = SHA-256(P || 0^48 || parts)[:16]. Leaf i of a tree is the one-time
key at epoch i. Key derivation (not specified by hbs_bench) mirrors PR 1088: see `tree_seeds`.
"""

import hashlib

N = 16
SETS = {
    # name: (chunk_bits, chains, target_sum)
    "w256": (8, 18, 2525),
    "w16": (4, 34, 281),
}

DS_KEY_SEED = b"/LEE/v0.3/KeySeed/" + b"\x00" * 14
KEY_TYPE_TSW = 2  # hypothetical KeyType byte; PR 1088 defines only Wots = 0, Schnorr = 1


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def tree_seeds(secret, nonce):
    """(sk_seed: 32 B, P: 16 B) for one nonce, mirroring PR 1088's key_seed and expand."""
    seed = sha256(DS_KEY_SEED, secret, bytes([KEY_TYPE_TSW]), nonce.to_bytes(16, "little"))
    return sha256(b"TswTree/v1/SK.seed", seed), sha256(b"TswTree/v1/PK.seed", seed)[:N]


class Tsw:
    def __init__(self, name):
        self.cb, self.v, self.t = SETS[name]
        self.w = 1 << self.cb

    @staticmethod
    def th(p, *parts):
        return sha256(p, b"\x00" * (64 - len(p)), *parts)[:N]

    def chain_start(self, sk, epoch, i):
        return sha256(sk, b"\x03", epoch.to_bytes(4, "big"), bytes([i]))[:N]

    def walk(self, p, epoch, i, x, frm, to):
        for pos in range(frm, to):
            x = self.th(p, b"\x00" + epoch.to_bytes(4, "big") + bytes([i, (pos + 1) & 0xFF]), x)
        return x

    def chunks(self, d):
        if self.cb == 8:
            return list(d[: self.v])
        out = []
        for b in d:
            out += [b >> 4, b & 0xF]
        return out[: self.v]

    def encode(self, p, rho, epoch, msg):
        c = self.chunks(sha256(rho, p, b"\x02", epoch.to_bytes(4, "big"), msg))
        return c if sum(c) == self.t else None

    def leaf(self, sk, p, epoch):
        ends = b"".join(
            self.walk(p, epoch, i, self.chain_start(sk, epoch, i), 0, self.w - 1) for i in range(self.v)
        )
        return self.th(p, b"\x01" + epoch.to_bytes(4, "big"), ends)

    def grind(self, sk, p, epoch, msg):
        """Deterministic rho as in hbs_bench: SHA-256(sk || 04 || epoch || msg || ctr)[:16]."""
        ctr = 0
        while True:
            rho = sha256(sk, b"\x04", epoch.to_bytes(4, "big"), msg, ctr.to_bytes(8, "big"))[:N]
            ctr += 1
            c = self.encode(p, rho, epoch, msg)
            if c is not None:
                return rho, c, ctr

    def ots_sign(self, sk, p, epoch, msg, rho=None):
        if rho is None:
            rho, c, tries = self.grind(sk, p, epoch, msg)
        else:
            c, tries = self.encode(p, rho, epoch, msg), 0
            assert c is not None
        sig = rho + b"".join(self.walk(p, epoch, i, self.chain_start(sk, epoch, i), 0, ci) for i, ci in enumerate(c))
        return sig, tries

    def merkle(self, p, leaves):
        h = len(leaves).bit_length() - 1
        levels = [list(leaves)]
        for lv in range(h):
            prev = levels[-1]
            levels.append(
                [self.th(p, b"\x05" + bytes([lv + 1]) + j.to_bytes(4, "big"), prev[2 * j], prev[2 * j + 1])
                 for j in range(len(prev) // 2)]
            )
        paths = [b"".join(levels[lv][(i >> lv) ^ 1] for lv in range(h)) for i in range(len(leaves))]
        return levels[-1][0], paths

    def tree_verify(self, p, root, keys, msg, sig):
        h = keys.bit_length() - 1
        if len(sig) != 1 + N + self.v * N + h * N or sig[0] >= keys:
            return False
        leaf, rho = sig[0], sig[1 : 1 + N]
        vals, auth = sig[1 + N : 1 + N + self.v * N], sig[1 + N + self.v * N :]
        c = self.encode(p, rho, leaf, msg)
        if c is None:
            return False
        ends = b"".join(
            self.walk(p, leaf, i, vals[i * N : (i + 1) * N], ci, self.w - 1) for i, ci in enumerate(c)
        )
        node = self.th(p, b"\x01" + leaf.to_bytes(4, "big"), ends)
        for lv in range(h):
            a = auth[lv * N : (lv + 1) * N]
            t = b"\x05" + bytes([lv + 1]) + (leaf >> (lv + 1)).to_bytes(4, "big")
            node = self.th(p, t, node, a) if (leaf >> lv) & 1 == 0 else self.th(p, t, a, node)
        return node == root


def _self_test():
    # Vectors printed by hbs_bench's unmodified tsw.rs: sk_seed = 00..1f, P = a0..af,
    # M = ab * 32, signing with leaf 1.
    sk, p, msg = bytes(range(32)), bytes(range(0xA0, 0xB0)), b"\xab" * 32
    expected = {
        ("w256", 2): ("0b0545ddd96aa27d8908cd3c07d693e7", 337, "53db0b7ee4c5bcb0137bc9dd2ce827ff55601774b9a7a07d69ed41d303fa115d"),
        ("w256", 3): ("b26b77bb76f5eefbe35dbce92305f1dc", 353, "9214ce1d9937a5af482aa86df7fd3b7658379fbcc642c6b643ec7d637e589498"),
        ("w16", 2): ("913461f4c4063af12d4ab7b94bad28a7", 593, "3b794b005cc8d6f8ac6b80642d7317d54a54d71688c7e6878e117fe176ef2a32"),
        ("w16", 3): ("4ec57b07f5e19139a29a8cf544838472", 609, "07094564d9b76e59804bf16bf7a83d4c821f80268df4edfabd5582c79f788e1b"),
    }
    for name in SETS:
        s = Tsw(name)
        leaves = [s.leaf(sk, p, e) for e in range(8)]
        for h in (2, 3):
            root, paths = s.merkle(p, leaves[: 1 << h])
            ots, _ = s.ots_sign(sk, p, 1, msg)
            sig = b"\x01" + ots + paths[1]
            want_root, want_len, want_hash = expected[(name, h)]
            assert root.hex() == want_root and len(sig) == want_len and sha256(sig).hex() == want_hash, (name, h)
            assert s.tree_verify(p, root, 1 << h, msg, sig)
    print("TSW reference matches hbs_bench vectors (w=256 and w=16, K = 4 and 8)")


if __name__ == "__main__":
    _self_test()

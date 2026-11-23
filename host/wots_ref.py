"""Reference implementation of PR 1088's WOTS+ tree (lee/state_machine/src/signature/wots).

FIPS 205 WOTS+ at SLH-DSA-SHA2-128f parameters (n=16, w=16, len=35, h'=3), with the key
derivation, message digest and 625-byte layout from PR 1088's SPEC.md. Used as the oracle the
card's output is checked against.
"""

import hashlib
import hmac

N = 16
W = 16
LEN1, LEN2 = 32, 3
LEN = LEN1 + LEN2
LEAVES = 8
HEIGHT = 3

# FIPS 205 address types.
WOTS_HASH, WOTS_PK, TREE, WOTS_PRF = 0, 1, 2, 5

DS_KEY_SEED = b"/LEE/v0.3/KeySeed/" + b"\x00" * 14
KEY_TYPE_WOTS = 0


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def adrs_c(typ, keypair=0, chain_or_height=0, hash_or_index=0):
    """Compressed 22-byte address (FIPS 205 §11.2) with layer 0 and tree 0."""
    return (
        b"\x00"  # layer address, low byte
        + b"\x00" * 8  # tree address, low 8 bytes
        + bytes([typ])
        + keypair.to_bytes(4, "big")
        + chain_or_height.to_bytes(4, "big")
        + hash_or_index.to_bytes(4, "big")
    )


def thash(pk_seed, adrs, m):
    """F, H, T_l and PRF for SHA2 at Category 1: Trunc_n(SHA-256(PK.seed || 0^48 || ADRSc || M))."""
    return sha256(pk_seed, b"\x00" * (64 - N), adrs, m)[:N]


def key_seed(secret, nonce):
    return sha256(DS_KEY_SEED, secret, bytes([KEY_TYPE_WOTS]), nonce.to_bytes(16, "little"))


def expand(seed):
    """(SK.seed, SK.prf, PK.seed) from a 32-byte tree seed."""
    return tuple(
        sha256(ds, seed)[:N]
        for ds in (b"WotsTree/v1/SK.seed", b"WotsTree/v1/SK.prf", b"WotsTree/v1/PK.seed")
    )


def chain(x, start, steps, pk_seed, leaf, j):
    for k in range(start, start + steps):
        x = thash(pk_seed, adrs_c(WOTS_HASH, leaf, j, k), x)
    return x


def chain_sk(sk_seed, pk_seed, leaf, j):
    return thash(pk_seed, adrs_c(WOTS_PRF, leaf, j, 0), sk_seed)


def leaf_pk(sk_seed, pk_seed, leaf):
    """WOTS+ public key of key pair `leaf`, compressed with T_len: the tree's leaf node."""
    ends = b"".join(
        chain(chain_sk(sk_seed, pk_seed, leaf, j), 0, W - 1, pk_seed, leaf, j) for j in range(LEN)
    )
    return thash(pk_seed, adrs_c(WOTS_PK, leaf), ends)


def base_w(msg16):
    digits = []
    for b in msg16:
        digits += [b >> 4, b & 0xF]
    csum = sum(W - 1 - d for d in digits) << 4
    c = csum.to_bytes(2, "big")
    digits += [c[0] >> 4, c[0] & 0xF, c[1] >> 4]
    return digits


def wots_sign(digest16, sk_seed, pk_seed, leaf):
    return b"".join(
        chain(chain_sk(sk_seed, pk_seed, leaf, j), 0, d, pk_seed, leaf, j)
        for j, d in enumerate(base_w(digest16))
    )


def wots_pk_from_sig(sig, digest16, pk_seed, leaf):
    ends = b"".join(
        chain(sig[j * N : (j + 1) * N], d, W - 1 - d, pk_seed, leaf, j)
        for j, d in enumerate(base_w(digest16))
    )
    return thash(pk_seed, adrs_c(WOTS_PK, leaf), ends)


def merkle(leaves, pk_seed):
    """Root and per-leaf authentication paths (FIPS 205 Algorithms 9/10); 2^height leaves."""
    height = len(leaves).bit_length() - 1
    assert len(leaves) == 1 << height
    levels = [list(leaves)]
    for z in range(1, height + 1):
        prev = levels[-1]
        levels.append(
            [thash(pk_seed, adrs_c(TREE, 0, z, i), prev[2 * i] + prev[2 * i + 1]) for i in range(len(prev) // 2)]
        )
    root = levels[-1][0]
    paths = [b"".join(levels[z][(i >> z) ^ 1] for z in range(height)) for i in range(len(leaves))]
    return root, paths


def root_from_leaf(node, leaf, path, pk_seed):
    for z in range(len(path) // N):
        sib = path[z * N : (z + 1) * N]
        idx = leaf >> (z + 1)
        pair = node + sib if (leaf >> z) & 1 == 0 else sib + node
        node = thash(pk_seed, adrs_c(TREE, 0, z + 1, idx), pair)
    return node


def prf_msg(sk_prf, pk_seed, m):
    return hmac.new(sk_prf, pk_seed + m, hashlib.sha256).digest()[:N]


def h_msg16(r, pk_seed, root, m):
    """First 16 bytes of MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || root || M))."""
    return sha256(r, pk_seed, sha256(r, pk_seed, root, m), b"\x00\x00\x00\x00")[:N]


class Tree:
    def __init__(self, seed, keys=LEAVES):
        self.sk_seed, self.sk_prf, self.pk_seed = expand(seed)
        self.leaves = [leaf_pk(self.sk_seed, self.pk_seed, i) for i in range(keys)]
        self.root, self.paths = merkle(self.leaves, self.pk_seed)

    def public_key(self):
        return self.pk_seed + self.root

    def sign(self, leaf, m):
        r = prf_msg(self.sk_prf, self.pk_seed, m)
        d = h_msg16(r, self.pk_seed, self.root, m)
        return bytes([leaf]) + r + wots_sign(d, self.sk_seed, self.pk_seed, leaf) + self.paths[leaf]


def assemble(leaf, r_and_sig, path):
    """PR 1088's 625-byte auth data from the card's R || WOTS+ signature and the host's path."""
    return bytes([leaf]) + r_and_sig + path


def verify(public_key, m, auth, keys=LEAVES):
    height = keys.bit_length() - 1
    if len(auth) != 1 + N + LEN * N + height * N or auth[0] >= keys:
        return False
    pk_seed, root = public_key[:N], public_key[N:]
    leaf, r = auth[0], auth[1 : 1 + N]
    sig, path = auth[1 + N : 1 + N + LEN * N], auth[1 + N + LEN * N :]
    d = h_msg16(r, pk_seed, root, m)
    node = wots_pk_from_sig(sig, d, pk_seed, leaf)
    return root_from_leaf(node, leaf, path, pk_seed) == root


def _self_test():
    # Known answers from PR 1088: wots/tree.rs `fixed_seed_vectors`.
    t = Tree(bytes(range(32)))
    assert t.public_key().hex() == "82e8ce66e2dda65233dc06e067c6cb01d9fede44a6f92a004277afdd6ade41a9"
    auth = t.sign(5, b"\xab" * 32)
    assert auth[:48].hex() == (
        "0569538180c60a068ddc9f6a0935df1ffa28e2037c714ac9bfaf03ccb80d21bf"
        "6ffc0c057a10f75f972784cd08c49ef8"
    )
    assert sha256(auth).hex() == "6883b240bb47d7ba57908d5a72b89c5e54e0b8100c8ef9ecf44a662d6807c015"
    assert verify(t.public_key(), b"\xab" * 32, auth)
    bad = bytearray(auth)
    bad[100] ^= 1
    assert not verify(t.public_key(), b"\xab" * 32, bytes(bad))
    # Known answer from PR 1088: signing_keys.rs `key_seed` layout (checked with the Schnorr
    # type byte, the only vector the PR gives).
    s = sha256(DS_KEY_SEED, b"\x07" * 32, b"\x01", (0).to_bytes(16, "little"))
    assert s.hex() == "fae55c59b7c627ad9eb58de366afbf662930f73911a32ef952b3a3710a251987"
    # K = 4 (height 2): every leaf signs and verifies, and the auth data is 609 bytes.
    t4 = Tree(bytes(range(32)), keys=4)
    assert t4.leaves == t.leaves[:4]
    for i in range(4):
        a4 = t4.sign(i, b"\x01" * 32)
        assert len(a4) == 609 and verify(t4.public_key(), b"\x01" * 32, a4, keys=4)
    print("reference matches PR 1088 vectors; K = 4 tree signs and verifies")


if __name__ == "__main__":
    _self_test()

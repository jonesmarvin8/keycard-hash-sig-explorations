package lee.wots;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.InitializedMessageDigest;
import javacard.security.MessageDigest;

/**
 * Test applet: FIPS 205 WOTS+ (SLH-DSA-SHA2-128f parameters: n = 16, w = 16, 35 chains) with
 * PR 1088's key derivation. The card computes single leaves and one-time signatures; the host
 * builds the height-3 Merkle tree and authentication path.
 *
 * TESTING ONLY: no PIN, no secure channel, secret loaded in plaintext, and nothing stops a leaf
 * from signing two different messages.
 */
public final class WotsApplet extends Applet {

    private static final byte CLA = (byte) 0x80;
    private static final byte INS_LOAD_SECRET = (byte) 0x10; // data: secret(32)
    private static final byte INS_SET_NONCE = (byte) 0x12;   // data: nonce(16, LE) -> PK.seed(16)
    private static final byte INS_GET_LEAF = (byte) 0x20;    // P1 leaf -> leaf node(16)
    private static final byte INS_SIGN = (byte) 0x30;        // P1 leaf, data root(16) || M(32)
    private static final byte INS_READ = (byte) 0x32;        // P1P2 offset -> R || WOTS+ sig chunk
    private static final byte INS_BENCH = (byte) 0x40;       // P1 mode, data count(2)
    private static final byte INS_PROBE = (byte) 0x42;       // -> capability flags
    private static final byte INS_TSW_SET_NONCE = (byte) 0x50; // P1 set (0 w=256, 1 w=16), nonce(16) -> P(16)
    private static final byte INS_TSW_GET_LEAF = (byte) 0x52;  // P1 leaf -> leaf(16)
    private static final byte INS_TSW_SIGN = (byte) 0x54;      // P1 leaf, M(32) [|| rho(16)] -> tries(2)

    private static final short N = 16;
    private static final short LEN = 35;
    private static final short W_MAX = 15;
    private static final short SIG_OUT_LEN = (short) (N + LEN * N); // R || 35 chain values = 576

    // FIPS 205 address types.
    private static final byte WOTS_HASH = 0;
    private static final byte WOTS_PK = 1;
    private static final byte WOTS_PRF = 5;

    // Layout of `buf`: PK.seed(16) || 0^48 || ADRSc(22) || M(16) || spill(16).
    private static final short OFF_ADRS = 64;
    private static final short OFF_TYPE = (short) (OFF_ADRS + 9);
    private static final short OFF_KEYPAIR = (short) (OFF_ADRS + 10);
    private static final short OFF_CHAIN = (short) (OFF_ADRS + 14);
    private static final short OFF_HASH = (short) (OFF_ADRS + 18);
    private static final short OFF_M = (short) (OFF_ADRS + 22); // 86
    private static final short THASH_IN = (short) (OFF_M + N);  // 102
    private static final short BUF_LEN = (short) (THASH_IN + N); // 118

    // TSW (hbs_bench tsw.rs) layout of `buf`: P(16) || 0^48 || tweak(7) || x(16) || spill(16).
    private static final short T_TWEAK = 64;
    private static final short T_X = 71;
    private static final short T_IN = 87;
    private static final byte KEY_TYPE_TSW = 2; // hypothetical; PR 1088 has Wots = 0, Schnorr = 1

    private static final byte[] DS_TSW_SK = {
        'T', 's', 'w', 'T', 'r', 'e', 'e', '/', 'v', '1', '/', 'S', 'K', '.', 's', 'e', 'e', 'd'
    };
    private static final byte[] DS_TSW_PK = {
        'T', 's', 'w', 'T', 'r', 'e', 'e', '/', 'v', '1', '/', 'P', 'K', '.', 's', 'e', 'e', 'd'
    };

    private static final byte[] DS_KEY_SEED = {
        '/', 'L', 'E', 'E', '/', 'v', '0', '.', '3', '/', 'K', 'e', 'y', 'S', 'e', 'e', 'd', '/',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    private static final byte[] DS_SK_SEED = {
        'W', 'o', 't', 's', 'T', 'r', 'e', 'e', '/', 'v', '1', '/', 'S', 'K', '.', 's', 'e', 'e', 'd'
    };
    private static final byte[] DS_SK_PRF = {
        'W', 'o', 't', 's', 'T', 'r', 'e', 'e', '/', 'v', '1', '/', 'S', 'K', '.', 'p', 'r', 'f'
    };
    private static final byte[] DS_PK_SEED = {
        'W', 'o', 't', 's', 'T', 'r', 'e', 'e', '/', 'v', '1', '/', 'P', 'K', '.', 's', 'e', 'e', 'd'
    };

    private final byte[] secret;      // persistent: the account's PublicAccountSecret
    private final byte[] buf;         // transient: tweakable-hash input
    private final byte[] work;        // transient: chain ends (leaf) or R || signature (sign)
    private final byte[] scratch;     // transient: 64 B for seeds, HMAC pads, digests
    private final byte[] keys;        // transient: SK.seed(16) || SK.prf(16)
    private final byte[] digits;      // transient: 35 base-w digits
    private final boolean[] state;    // transient: [0] WOTS+ nonce set, [1] signature ready, [2] TSW nonce set
    private final short[] outLen;     // transient: [0] length of the result READ returns
    private final byte[] tw;          // transient: short hash inputs (tweaks, counters)
    private byte tswBits;             // TSW chunk bits (8 or 4)
    private short tswV;               // TSW chains
    private short tswT;               // TSW target sum
    private final MessageDigest md;
    private InitializedMessageDigest imd; // allocated once, on first probe or bench mode 4
    private boolean imdProbed;

    private WotsApplet() {
        secret = new byte[32];
        buf = JCSystem.makeTransientByteArray(BUF_LEN, JCSystem.CLEAR_ON_DESELECT);
        work = JCSystem.makeTransientByteArray(SIG_OUT_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratch = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        keys = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        digits = JCSystem.makeTransientByteArray(LEN, JCSystem.CLEAR_ON_DESELECT);
        state = JCSystem.makeTransientBooleanArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        outLen = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        tw = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new WotsApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] apduBuf = apdu.getBuffer();
        if (apduBuf[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch (apduBuf[ISO7816.OFFSET_INS]) {
            case INS_LOAD_SECRET:
                loadSecret(apdu);
                break;
            case INS_SET_NONCE:
                setNonce(apdu);
                break;
            case INS_GET_LEAF:
                getLeaf(apdu);
                break;
            case INS_SIGN:
                sign(apdu);
                break;
            case INS_READ:
                read(apdu);
                break;
            case INS_BENCH:
                bench(apdu);
                break;
            case INS_PROBE:
                probe(apdu);
                break;
            case INS_TSW_SET_NONCE:
                tswSetNonce(apdu);
                break;
            case INS_TSW_GET_LEAF:
                tswGetLeaf(apdu);
                break;
            case INS_TSW_SIGN:
                tswSign(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private static short receive(APDU apdu, short expected) {
        short len = apdu.setIncomingAndReceive();
        if (len != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return ISO7816.OFFSET_CDATA;
    }

    private void loadSecret(APDU apdu) {
        short off = receive(apdu, (short) 32);
        Util.arrayCopy(apdu.getBuffer(), off, secret, (short) 0, (short) 32);
        state[0] = false;
        state[1] = false;
        state[2] = false;
    }

    /** key_seed = SHA-256(DS_KEY_SEED || secret || 0x00 (KeyType::Wots) || nonce as u128 LE). */
    private void setNonce(APDU apdu) {
        short off = receive(apdu, (short) 16);
        byte[] a = apdu.getBuffer();
        md.reset();
        md.update(DS_KEY_SEED, (short) 0, (short) 32);
        md.update(secret, (short) 0, (short) 32);
        scratch[0] = 0;
        md.update(scratch, (short) 0, (short) 1);
        md.doFinal(a, off, (short) 16, scratch, (short) 0); // scratch[0..32] = tree seed

        expand(DS_SK_SEED, keys, (short) 0);
        expand(DS_SK_PRF, keys, N);
        expand(DS_PK_SEED, buf, (short) 0); // PK.seed sits at the front of every tweakable hash
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(buf, N, (short) (OFF_ADRS - N), (byte) 0);
        Util.arrayFillNonAtomic(buf, OFF_ADRS, (short) 22, (byte) 0);

        state[0] = true;
        state[1] = false;
        state[2] = false;
        Util.arrayCopyNonAtomic(buf, (short) 0, a, (short) 0, N);
        apdu.setOutgoingAndSend((short) 0, N);
    }

    /** SHA-256(ds || tree seed in scratch[0..32])[0..16] into out[outOff..]. */
    private void expand(byte[] ds, byte[] out, short outOff) {
        md.reset();
        md.update(ds, (short) 0, (short) ds.length);
        md.doFinal(scratch, (short) 0, (short) 32, scratch, (short) 32);
        Util.arrayCopyNonAtomic(scratch, (short) 32, out, outOff, N);
    }

    private void requireNonce() {
        if (!state[0]) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private static byte leafIndex(byte[] a) {
        byte leaf = a[ISO7816.OFFSET_P1];
        if (leaf < 0 || leaf > 7) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return leaf;
    }

    private void setAddress(byte type, byte keypair, byte chain, byte hash) {
        buf[OFF_TYPE] = type;
        buf[(short) (OFF_KEYPAIR + 3)] = keypair;
        buf[(short) (OFF_CHAIN + 3)] = chain;
        buf[(short) (OFF_HASH + 3)] = hash;
    }

    /** Chain secret: PRF(PK.seed, SK.seed, ADRS) into buf[OFF_M..]. */
    private void chainSecret(byte leaf, byte j) {
        setAddress(WOTS_PRF, leaf, j, (byte) 0);
        Util.arrayCopyNonAtomic(keys, (short) 0, buf, OFF_M, N);
        md.doFinal(buf, (short) 0, THASH_IN, buf, OFF_M);
    }

    /** Advances buf[OFF_M..] along chain j of `leaf` by `steps` F calls starting at `start`. */
    private void chain(byte leaf, byte j, short start, short steps) {
        setAddress(WOTS_HASH, leaf, j, (byte) start);
        short end = (short) (start + steps);
        for (short k = start; k < end; k++) {
            buf[(short) (OFF_HASH + 3)] = (byte) k;
            // In place: the 32-byte output overwrites M and spills into the last 16 bytes.
            md.doFinal(buf, (short) 0, THASH_IN, buf, OFF_M);
        }
    }

    private void getLeaf(APDU apdu) {
        requireNonce();
        byte[] a = apdu.getBuffer();
        byte leaf = leafIndex(a);
        for (byte j = 0; j < LEN; j++) {
            chainSecret(leaf, j);
            chain(leaf, j, (short) 0, W_MAX);
            Util.arrayCopyNonAtomic(buf, OFF_M, work, (short) (j * N), N);
        }
        // T_len over the 35 chain ends: SHA-256(PK.seed || 0^48 || ADRSc || ends).
        setAddress(WOTS_PK, leaf, (byte) 0, (byte) 0);
        md.update(buf, (short) 0, OFF_M);
        md.doFinal(work, (short) 0, (short) (LEN * N), scratch, (short) 0);
        Util.arrayCopyNonAtomic(scratch, (short) 0, a, (short) 0, N);
        apdu.setOutgoingAndSend((short) 0, N);
    }

    private void sign(APDU apdu) {
        requireNonce();
        byte[] a = apdu.getBuffer();
        byte leaf = leafIndex(a);
        short off = receive(apdu, (short) (N + 32));
        short rootOff = off;
        short msgOff = (short) (off + N);

        // R = HMAC-SHA-256(SK.prf, PK.seed || M)[0..16]  (PRF_msg, opt_rand = PK.seed).
        hmacPad((byte) 0x36);
        md.update(scratch, (short) 0, (short) 64);
        md.update(buf, (short) 0, N);
        md.doFinal(a, msgOff, (short) 32, work, (short) 0);
        hmacPad((byte) 0x5c);
        md.update(scratch, (short) 0, (short) 64);
        md.doFinal(work, (short) 0, (short) 32, scratch, (short) 0);
        Util.arrayCopyNonAtomic(scratch, (short) 0, work, (short) 0, N); // work[0..16] = R

        // digest = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || root || M))[0..16].
        md.update(work, (short) 0, N);
        md.update(buf, (short) 0, N);
        md.update(a, rootOff, N);
        md.doFinal(a, msgOff, (short) 32, scratch, (short) 32);
        Util.arrayCopyNonAtomic(work, (short) 0, scratch, (short) 0, N);
        Util.arrayCopyNonAtomic(buf, (short) 0, scratch, N, N);
        Util.arrayFillNonAtomic(work, N, (short) 4, (byte) 0); // MGF1 counter 0
        md.update(scratch, (short) 0, (short) 64);
        md.doFinal(work, N, (short) 4, scratch, (short) 0);

        // Base-w digits of the 16-byte digest, then the 3-digit checksum.
        short csum = 0;
        for (short i = 0; i < N; i++) {
            byte hi = (byte) ((scratch[i] >> 4) & 0x0F);
            byte lo = (byte) (scratch[i] & 0x0F);
            digits[(short) (2 * i)] = hi;
            digits[(short) (2 * i + 1)] = lo;
            csum += (short) (2 * W_MAX - hi - lo);
        }
        csum <<= 4;
        digits[32] = (byte) ((csum >> 12) & 0x0F);
        digits[33] = (byte) ((csum >> 8) & 0x0F);
        digits[34] = (byte) ((csum >> 4) & 0x0F);

        for (byte j = 0; j < LEN; j++) {
            chainSecret(leaf, j);
            chain(leaf, j, (short) 0, digits[j]);
            Util.arrayCopyNonAtomic(buf, OFF_M, work, (short) (N + j * N), N);
        }
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, (byte) 0);
        outLen[0] = SIG_OUT_LEN;
        state[1] = true;
    }

    /** scratch[0..64] = (SK.prf || 0^48) XOR pad. */
    private void hmacPad(byte pad) {
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, pad);
        for (short i = 0; i < N; i++) {
            scratch[i] ^= keys[(short) (N + i)];
        }
    }

    private void read(APDU apdu) {
        if (!state[1]) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] a = apdu.getBuffer();
        short off = Util.getShort(a, ISO7816.OFFSET_P1);
        short total = outLen[0];
        if (off < 0 || off >= total) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short len = apdu.setOutgoing();
        if (len == 0 || len > (short) (total - off)) {
            len = (short) (total - off);
        }
        if (len > 255) {
            len = 255;
        }
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(work, off, len);
    }

    /**
     * Mode 0: empty loop. Mode 1: SHA-256 of 55 B (one block). Mode 2: F-shaped 102 B in place
     * (two blocks). Mode 3: 646 B (T_len-shaped, eleven blocks). Mode 4: one F via a
     * precomputed-midstate InitializedMessageDigest (38 B after a 64 B prefix), if supported.
     */
    private void bench(APDU apdu) {
        byte[] a = apdu.getBuffer();
        byte mode = a[ISO7816.OFFSET_P1];
        short off = receive(apdu, (short) 2);
        short count = Util.getShort(a, off);
        if (mode == 4) {
            if (initializedDigest() == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            Util.arrayFillNonAtomic(scratch, (short) 0, (short) 32, (byte) 0x6a);
            Util.arrayFillNonAtomic(scratch, (short) 32, (short) 8, (byte) 0);
            scratch[39] = 0x40; // 64 bytes already digested, as an 8-byte big-endian count
        }
        for (short i = 0; i < count; i++) {
            switch (mode) {
                case 1:
                    md.doFinal(buf, (short) 0, (short) 55, buf, OFF_M);
                    break;
                case 2:
                    md.doFinal(buf, (short) 0, THASH_IN, buf, OFF_M);
                    break;
                case 3:
                    md.update(buf, (short) 0, OFF_M);
                    md.doFinal(work, (short) 0, (short) (LEN * N), buf, OFF_M);
                    break;
                case 4:
                    imd.setInitialDigest(scratch, (short) 0, (short) 32, scratch, (short) 32, (short) 8);
                    imd.doFinal(buf, OFF_ADRS, (short) 38, buf, OFF_M);
                    break;
                default:
                    break;
            }
        }
    }

    private InitializedMessageDigest initializedDigest() {
        if (!imdProbed) {
            imdProbed = true;
            try {
                imd = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, false);
            } catch (CryptoException e) {
                imd = null;
            }
        }
        return imd;
    }

    /** Bit 0: InitializedMessageDigest for SHA-256 is available. */
    private void probe(APDU apdu) {
        byte[] a = apdu.getBuffer();
        a[0] = (byte) (initializedDigest() != null ? 1 : 0);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // ---------------- Target-sum Winternitz (hbs_bench tsw.rs, n = |P| = |rho| = 16) ----------------

    /** seed = SHA-256(DS_KEY_SEED || secret || 0x02 || nonce LE); sk = SHA-256(DS_SK || seed); P = SHA-256(DS_PK || seed)[0..16]. */
    private void tswSetNonce(APDU apdu) {
        byte[] a = apdu.getBuffer();
        byte set = a[ISO7816.OFFSET_P1];
        if (set == 0) {
            tswBits = 8;
            tswV = 18;
            tswT = 2525;
        } else if (set == 1) {
            tswBits = 4;
            tswV = 34;
            tswT = 281;
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short off = receive(apdu, (short) 16);
        md.reset();
        md.update(DS_KEY_SEED, (short) 0, (short) 32);
        md.update(secret, (short) 0, (short) 32);
        scratch[0] = KEY_TYPE_TSW;
        md.update(scratch, (short) 0, (short) 1);
        md.doFinal(a, off, (short) 16, scratch, (short) 0);
        md.update(DS_TSW_SK, (short) 0, (short) DS_TSW_SK.length);
        md.doFinal(scratch, (short) 0, (short) 32, keys, (short) 0); // keys = sk_seed (32)
        md.update(DS_TSW_PK, (short) 0, (short) DS_TSW_PK.length);
        md.doFinal(scratch, (short) 0, (short) 32, scratch, (short) 32);
        Util.arrayCopyNonAtomic(scratch, (short) 32, buf, (short) 0, N);
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(buf, N, (short) (T_TWEAK - N), (byte) 0);
        state[0] = false;
        state[1] = false;
        state[2] = true;
        Util.arrayCopyNonAtomic(buf, (short) 0, a, (short) 0, N);
        apdu.setOutgoingAndSend((short) 0, N);
    }

    private void requireTsw() {
        if (!state[2]) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /** tw[0..5] = prefix || epoch as 4 bytes BE (epoch is a leaf index below 8). */
    private void tswPrefix(byte prefix, byte epoch) {
        tw[0] = prefix;
        tw[1] = 0;
        tw[2] = 0;
        tw[3] = 0;
        tw[4] = epoch;
    }

    /** buf[T_X..] = SHA-256(sk_seed || 03 || epoch || i), of which the first 16 bytes are used. */
    private void tswChainStart(byte epoch, byte i) {
        tswPrefix((byte) 3, epoch);
        tw[5] = i;
        md.update(keys, (short) 0, (short) 32);
        md.doFinal(tw, (short) 0, (short) 6, buf, T_X);
    }

    /** Steps buf[T_X..T_X+16] from position `from` to `to`, tweak 00 || epoch || i || pos+1. */
    private void tswWalk(byte epoch, byte i, short from, short to) {
        buf[T_TWEAK] = 0;
        buf[(short) (T_TWEAK + 1)] = 0;
        buf[(short) (T_TWEAK + 2)] = 0;
        buf[(short) (T_TWEAK + 3)] = 0;
        buf[(short) (T_TWEAK + 4)] = epoch;
        buf[(short) (T_TWEAK + 5)] = i;
        for (short pos = from; pos < to; pos++) {
            buf[(short) (T_TWEAK + 6)] = (byte) (pos + 1);
            md.doFinal(buf, (short) 0, T_IN, buf, T_X);
        }
    }

    private void tswGetLeaf(APDU apdu) {
        requireTsw();
        byte[] a = apdu.getBuffer();
        byte leaf = leafIndex(a);
        short top = (short) ((short) (1 << tswBits) - 1);
        for (byte i = 0; i < tswV; i++) {
            tswChainStart(leaf, i);
            tswWalk(leaf, i, (short) 0, top);
            Util.arrayCopyNonAtomic(buf, T_X, work, (short) (i * N), N);
        }
        // Th(P, 01 || epoch, ends)
        tswPrefix((byte) 1, leaf);
        md.update(buf, (short) 0, T_TWEAK);
        md.update(tw, (short) 0, (short) 5);
        md.doFinal(work, (short) 0, (short) (tswV * N), scratch, (short) 0);
        Util.arrayCopyNonAtomic(scratch, (short) 0, a, (short) 0, N);
        apdu.setOutgoingAndSend((short) 0, N);
    }

    /** Chunks of SHA-256(rho=work[0..16] || P || 02 || epoch || M) into `digits`; returns their sum. */
    private short tswEncode(byte epoch, byte[] a, short msgOff) {
        md.update(work, (short) 0, N);
        md.update(buf, (short) 0, N);
        tswPrefix((byte) 2, epoch);
        md.update(tw, (short) 0, (short) 5);
        md.doFinal(a, msgOff, (short) 32, scratch, (short) 0);
        short sum = 0;
        if (tswBits == 8) {
            for (short i = 0; i < tswV; i++) {
                digits[i] = scratch[i];
                sum += (short) (scratch[i] & 0xFF);
            }
        } else {
            for (short i = 0; i < tswV; i++) {
                byte b = scratch[(short) (i >> 1)];
                byte d = (byte) (((i & 1) == 0 ? (b >> 4) : b) & 0x0F);
                digits[i] = d;
                sum += d;
            }
        }
        return sum;
    }

    private void tswSign(APDU apdu) {
        requireTsw();
        byte[] a = apdu.getBuffer();
        byte leaf = leafIndex(a);
        short len = apdu.setIncomingAndReceive();
        short msgOff = ISO7816.OFFSET_CDATA;
        short tries = 0;
        if (len == (short) (32 + N)) {
            // Host-chosen rho: check it hits the target sum.
            Util.arrayCopyNonAtomic(a, (short) (msgOff + 32), work, (short) 0, N);
            if (tswEncode(leaf, a, msgOff) != tswT) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        } else if (len == 32) {
            // rho = SHA-256(sk_seed || 04 || epoch || M || ctr as 8 bytes BE)[0..16], ctr = 0, 1, ...
            Util.arrayFillNonAtomic(tw, (short) 8, (short) 8, (byte) 0);
            while (true) {
                md.update(keys, (short) 0, (short) 32);
                tswPrefix((byte) 4, leaf);
                md.update(tw, (short) 0, (short) 5);
                md.update(a, msgOff, (short) 32);
                md.doFinal(tw, (short) 8, (short) 8, scratch, (short) 0);
                Util.arrayCopyNonAtomic(scratch, (short) 0, work, (short) 0, N);
                tries++;
                for (short k = 15; k >= 8; k--) { // ctr += 1
                    if (++tw[k] != 0) {
                        break;
                    }
                }
                if (tswEncode(leaf, a, msgOff) == tswT) {
                    break;
                }
                if (tries == 32000) {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        for (byte i = 0; i < tswV; i++) {
            short c = (short) (digits[i] & 0xFF);
            tswChainStart(leaf, i);
            tswWalk(leaf, i, (short) 0, c);
            Util.arrayCopyNonAtomic(buf, T_X, work, (short) (N + i * N), N);
        }
        Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, (byte) 0);
        outLen[0] = (short) (N + tswV * N);
        state[1] = true;
        Util.setShort(a, (short) 0, tries);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }
}

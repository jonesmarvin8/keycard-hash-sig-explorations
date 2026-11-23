# keycard-wots

Test applet: FIPS 205 WOTS+ (n = 16, w = 16, 35 chains, PR 1088's key derivation) and target-sum Winternitz (TSW, ported from `hbs_bench`'s `tsw.rs`, w = 256 or 16) on a Keycard (JCOP4, JavaCard 3.0.4).

The card computes single leaves and one-time signatures. The host builds the Merkle tree (K = 1, 2, 4 or 8 leaves) and the authentication path, assembles the full signature (for WOTS+ with K = 8, PR 1088's 625-byte auth data) and verifies it.

**Testing only:** there is no PIN and no secure channel, the secret is loaded in plaintext, and nothing stops a leaf from signing two different messages. TSW key derivation uses a placeholder key-type byte `0x02`.

## Layout

| Path | What |
| --- | --- |
| `applet/src/lee/wots/WotsApplet.java` | The applet |
| `applet/build.sh` | Builds `applet/WotsApplet.cap` (JC 3.2 SDK converter, `-target 3.0.4`) |
| `host/wots_ref.py` | Python reference, checked against PR 1088's known answers (`python3 host/wots_ref.py`) |
| `host/run.py` | Drives the card or the simulator, checks every result against the reference, and times each step |
| `host/tsw_ref.py`, `host/tsw_run.py` | TSW reference (checked against `hbs_bench` vectors) and driver |
| `host/pcsc.py` | Minimal PC/SC over the system `libpcsclite` (ctypes) |
| `sim/` | jCardSim bridge (`python3 host/run.py --sim`) |
| `third_party/` | Downloaded: Oracle JavaCard SDKs, `gp.jar` (GlobalPlatformPro), `jcardsim.jar` |

## APDUs (CLA 0x80, applet AID `F04C4545574F545301`)

| INS | P1 | Data | Response |
| --- | --- | --- | --- |
| `10` LOAD_SECRET | | secret (32) | |
| `12` SET_NONCE | | nonce (16, u128 LE) | PK.seed (16) |
| `20` GET_LEAF | leaf | | leaf node (16) |
| `30` SIGN | leaf | root (16) ‖ M (32) | (result kept on the card) |
| `32` READ | P1P2 = offset | | last signature: R ‖ chain values, in chunks |
| `40` BENCH | mode 0–4 | count (2, BE) | |
| `42` PROBE | | | bit 0: `InitializedMessageDigest` is supported |
| `50` TSW_SET_NONCE | 0 = w256, 1 = w16 | nonce (16, u128 LE) | P (16) |
| `52` TSW_GET_LEAF | leaf (= epoch) | | leaf (16) |
| `54` TSW_SIGN | leaf | M (32) [‖ ρ (16)] | card grinding tries (2); without ρ the card grinds |

## On the card

Keycard development cards use the Keycard dev GlobalPlatform key (SCP02), published in Keycard's own README. If any `gp` command fails to authenticate, stop: every failed authentication counts toward the card manager's lock.

```
K=c212e073ff8b4bbfaff4de8ab655221f
java -jar third_party/gp.jar --info                                  # read only
java -jar third_party/gp.jar --key $K --list
java -jar third_party/gp.jar --key $K --install applet/WotsApplet.cap
python3 host/run.py --bench 200 --keys 4                             # WOTS+: benchmark, leaves, sign, verify
python3 host/tsw_run.py --set w16 --keys 4                           # TSW (w16 or w256), add --host-rho to grind on the host
java -jar third_party/gp.jar --key $K --uninstall applet/WotsApplet.cap
```

## Setup

`third_party/` is not committed. Fetch it with:

```
mkdir -p third_party && cd third_party
git clone --depth 1 https://github.com/martinpaljak/oracle_javacard_sdks.git
curl -sSLo gp.jar https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar
curl -sSLo jcardsim.jar https://repo1.maven.org/maven2/com/klinec/jcardsim/3.0.6.0/jcardsim-3.0.6.0.jar
```

Needs a JDK (11+ for `javac --release 8`; 17+ to run the JC 3.2 converter) and Python 3 with no extra packages.

`run.py` options: `--secret HEX`, `--nonce N`, `--leaf I`, `--message HEX`, `--bench COUNT` (0 skips the benchmark), `--sim`.

## Results (Keycard dev card, ACS ACR39U)

| Scheme | Params | K | One leaf (s) | All K leaves (s) | Sign, card ρ (s) | Sign, host ρ (s) | Per tx (s) | Signature (B) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| WOTS+ (FIPS 205) | w=16, n=16, 35 chains | 8 | 2.29 | 18.36 | 1.17 | – | 19.5 | 625 |
| WOTS+ (FIPS 205) | w=16, n=16, 35 chains | 4 | 2.29 | 9.18 | 1.17 | – | 10.4 | 609 |
| TSW | w=16, n=16, 34 chains, T=281 | 4 | 2.17 | 8.69 | 3.16 (105 tries) | 1.25 | 9.9–11.9 | 593 |
| TSW | w=256, n=16, 18 chains, T=2525 | 4 | 19.00 | 75.99 | 28.02 (1,175 tries) | 10.46 | 86–104 | 337 |

SHA-256 on the card: 2.39 ms for one block, 3.77 ms for a 2-block F call, ~1 ms of it per-call overhead; midstate (`InitializedMessageDigest`) gives no speed-up. Per tx = all K leaves of the next tree plus one signature. Grinding tries depend on the message. All schemes are NIST Category 1 by best known attack (n = 16), and only while each leaf signs one message.

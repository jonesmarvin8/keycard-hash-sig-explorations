#!/usr/bin/env bash
# Builds WotsApplet.cap for JavaCard 3.0.4 (JCOP4) with the JC 3.2 SDK's converter.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kit="$here/../third_party/oracle_javacard_sdks/jc320v26.0_kit"
out="$here/build"
rm -rf "$out" && mkdir -p "$out/classes"

javac --release 8 -nowarn -g:none \
  -cp "$kit/lib/api_classic-3.0.4.jar" \
  -d "$out/classes" "$here/src/lee/wots/WotsApplet.java"

# Package AID F0 'LEEWOTS'; applet AID adds 0x01. F0 = proprietary, for testing.
java -cp "$kit/lib/*" com.sun.javacard.converter.Main \
  -nobanner -target 3.0.4 \
  -classdir "$out/classes" -d "$out" -out CAP \
  -applet 0xF0:0x4C:0x45:0x45:0x57:0x4F:0x54:0x53:0x01 lee.wots.WotsApplet \
  lee.wots 0xF0:0x4C:0x45:0x45:0x57:0x4F:0x54:0x53 1.0

find "$out" -name '*.cap' -exec cp {} "$here/WotsApplet.cap" \;
ls -l "$here/WotsApplet.cap"

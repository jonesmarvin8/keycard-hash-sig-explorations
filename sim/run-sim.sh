#!/usr/bin/env bash
# Starts the jCardSim bridge with WotsApplet installed (built by applet/build.sh).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
jar="$here/../third_party/jcardsim.jar"
mkdir -p "$here/build"
javac -nowarn -cp "$jar:$here/../applet/build/classes" -d "$here/build" "$here/Sim.java"
exec java -cp "$jar:$here/../applet/build/classes:$here/build" Sim

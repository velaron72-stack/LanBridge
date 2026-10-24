#!/usr/bin/env bash
# Builds and runs the native self-test on the host (needs g++). Uses AddressSanitizer + UBSan.
set -euo pipefail
cd "$(dirname "$0")"
SRC=../app/src/main/cpp
OUT="${TMPDIR:-/tmp}/lanbridge_selftest"
g++ -std=c++17 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=undefined -pthread \
    -I"$SRC" selftest.cpp "$SRC"/util.cpp "$SRC"/crypto.cpp "$SRC"/offer.cpp "$SRC"/stun.cpp "$SRC"/protocol.cpp "$SRC"/ipv6.cpp "$SRC"/frag.cpp "$SRC"/engine.cpp "$SRC"/engine_group.cpp "$SRC"/engine_net.cpp "$SRC"/engine_tun.cpp "$SRC"/group.cpp "$SRC"/addr.cpp "$SRC"/udpio.cpp "$SRC"/plat.cpp \
    -o "$OUT"
"$OUT"

#!/usr/bin/env bash
# Cross-compiles the native self-test and the Wintun pump test for Windows (llvm-mingw) and runs both under Wine.
# Needs: LLVM_MINGW (toolchain dir), wine64 on PATH (or WINE=/path/to/wine64).
# Usage: run-win.sh [selftest|pump|all]   (default: all)
set -euo pipefail
cd "$(dirname "$0")"
SRC=../app/src/main/cpp
: "${LLVM_MINGW:?set LLVM_MINGW to the llvm-mingw directory}"
WORK="${TMPDIR:-/tmp}/lanbridge_win_tests"
mkdir -p "$WORK"
CXX="$LLVM_MINGW/bin/x86_64-w64-mingw32-clang++"
FLAGS=(-std=c++17 -O1 -g -Wall -Wextra -Wno-unused-parameter -D_WIN32_WINNT=0x0A00 -DNOMINMAX -I"$SRC")
CORE=("$SRC"/util.cpp "$SRC"/crypto.cpp "$SRC"/offer.cpp "$SRC"/stun.cpp "$SRC"/protocol.cpp "$SRC"/ipv6.cpp "$SRC"/frag.cpp
      "$SRC"/engine.cpp "$SRC"/engine_group.cpp "$SRC"/engine_net.cpp "$SRC"/engine_tun.cpp "$SRC"/group.cpp "$SRC"/addr.cpp
      "$SRC"/udpio.cpp "$SRC"/plat.cpp)
WINE_BIN="${WINE:-wine64}"
what="${1:-all}"
rc=0
if [[ $what == selftest || $what == all ]]; then
    "$CXX" "${FLAGS[@]}" selftest.cpp "${CORE[@]}" -static -lws2_32 -lbcrypt -o "$WORK/selftest.exe"
    "$WINE_BIN" "$WORK/selftest.exe" || rc=1
fi
if [[ $what == pump || $what == all ]]; then
    "$CXX" "${FLAGS[@]}" -shared fake_wintun.cpp -static -o "$WORK/fake_wintun.dll"
    "$CXX" "${FLAGS[@]}" wintun_pump_test.cpp "$SRC"/wintun_win.cpp "$SRC"/plat.cpp "$SRC"/util.cpp \
        -static -lws2_32 -liphlpapi -lbcrypt -lshell32 -o "$WORK/wintun_pump_test.exe"
    (cd "$WORK" && "$WINE_BIN" ./wintun_pump_test.exe) || rc=1
fi
exit $rc

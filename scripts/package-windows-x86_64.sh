#!/usr/bin/env bash
# Package the original legacy UDP client for Windows (MinGW/OpenCV).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="pvp-windows-x86_64-builder:latest"
OUT_DIR="${ROOT}/dist/pvp-windows-x86_64"
ZIP="${ROOT}/dist/pvp-windows-x86_64.zip"
MINGW_PREFIX=/usr/x86_64-w64-mingw32/sys-root/mingw

cd "$ROOT"

echo "==> Building Docker image ${IMAGE} (linux/amd64)..."
docker build --platform=linux/amd64 -f Dockerfile.windows-x86_64 -t "$IMAGE" .

echo "==> Compiling pvp for x86_64-pc-windows-gnu..."
docker run --rm --platform=linux/amd64 \
  -v "${ROOT}:/src" \
  -w /src \
  -e CARGO_HOME=/src/.cargo-win \
  -e CARGO_TARGET_DIR=/src/target-win \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    export PATH="/root/.cargo/bin:$PATH"
    export MINGW_PREFIX=/usr/x86_64-w64-mingw32/sys-root/mingw
    export PKG_CONFIG_ALLOW_CROSS=1
    export PKG_CONFIG_SYSROOT_DIR=/usr/x86_64-w64-mingw32/sys-root
    export PKG_CONFIG_PATH=${MINGW_PREFIX}/lib/pkgconfig
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
    export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
    export CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++
    export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
    export OPENCV_INCLUDE_PATHS=${MINGW_PREFIX}/include/opencv4
    export OPENCV_LINK_PATHS=${MINGW_PREFIX}/lib
    export OPENCV_LINK_LIBS=opencv_core470,opencv_imgproc470,opencv_highgui470,opencv_videoio470,opencv_imgcodecs470
    export OPENCV_STATIC=0
    export LIBCLANG_PATH=/usr/lib64
    rustup target add x86_64-pc-windows-gnu
    cargo build --release --features legacy --bin pvp-legacy --target x86_64-pc-windows-gnu -v
  '

EXE="${ROOT}/target-win/x86_64-pc-windows-gnu/release/pvp-legacy.exe"
if [[ ! -f "$EXE" ]]; then
  echo "error: missing $EXE" >&2
  exit 1
fi

echo "==> Assembling package in ${OUT_DIR}..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

cp "$EXE" "$OUT_DIR/pvp.exe"
cp "${ROOT}/config.example.json" "$OUT_DIR/config.example.json"
# Ship placeholders; never bundle the developer's private keys or relay token.
cp "${ROOT}/config.example.json" "$OUT_DIR/config.json"

# Copy required MinGW / OpenCV / Qt DLLs from the builder image
docker run --rm --platform=linux/amd64 \
  -v "${OUT_DIR}:/out" \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    M=/usr/x86_64-w64-mingw32/sys-root/mingw/bin
    # Core OpenCV modules we link
    for f in \
      libopencv_core470.dll \
      libopencv_imgproc470.dll \
      libopencv_highgui470.dll \
      libopencv_videoio470.dll \
      libopencv_imgcodecs470.dll \
      libopencv_flann470.dll \
      libopencv_features2d470.dll \
      libopencv_calib3d470.dll \
      libopencv_video470.dll \
      libopencv_dnn470.dll
    do
      [[ -f "$M/$f" ]] && cp -v "$M/$f" /out/ || true
    done
    # Common runtime deps (zlib, image codecs, Qt5 for highgui, GCC runtime)
    for f in \
      libgcc_s_seh-1.dll \
      libstdc++-6.dll \
      libwinpthread-1.dll \
      zlib1.dll \
      libpng16-16.dll \
      libjpeg-62.dll \
      libtiff-5.dll \
      libwebp-7.dll \
      libwebpmux-3.dll \
      libwebpdemux-2.dll \
      libsharpyuv-0.dll \
      libopenjp2-7.dll \
      liblzma-5.dll \
      libzstd.dll \
      libopus-0.dll \
      Qt5Core.dll \
      Qt5Gui.dll \
      Qt5Widgets.dll \
      Qt5Test.dll \
      libglib-2.0-0.dll \
      libgobject-2.0-0.dll \
      libintl-8.dll \
      libpcre2-16-0.dll \
      libpcre2-8-0.dll \
      libiconv-2.dll \
      libdouble-conversion.dll \
      libharfbuzz-0.dll \
      libfreetype-6.dll \
      libbz2-1.dll \
      libbrotlidec.dll \
      libbrotlicommon.dll \
      libgraphite2.dll
    do
      [[ -f "$M/$f" ]] && cp -v "$M/$f" /out/ || true
    done
    # Qt platform plugin (required for highgui windows)
    mkdir -p /out/platforms
    if [[ -f /usr/x86_64-w64-mingw32/sys-root/mingw/lib/qt5/plugins/platforms/qwindows.dll ]]; then
      cp -v /usr/x86_64-w64-mingw32/sys-root/mingw/lib/qt5/plugins/platforms/qwindows.dll /out/platforms/
    fi
    # Any remaining opencv DLLs (safe bulk copy of small set)
    cp -n "$M"/libopencv_*.dll /out/ 2>/dev/null || true
  '

cat > "${OUT_DIR}/README-WINDOWS.txt" <<'EOF'
pvp for Windows x86_64
======================

1. Keep ALL files in this folder together (pvp.exe, DLLs, platforms\, config.json).
2. Edit config.json:
   - encryption_key: same 64-hex key as your peer
   - relay.token / relay.room / relay.server if using the TURN relay
3. Double-click pvp.exe or run from PowerShell:
     .\pvp.exe
4. Allow Windows Firewall if prompted (UDP 5000 for direct P2P).
5. Prefer direct P2P: enter peer's public IP:port from STUN printout.
   Or press Enter to use the configured relay.
6. ESC in the video window quits.

Notes:
- Requires a webcam and microphone.
- Built with MinGW + OpenCV 4.7 (Qt highgui).
- If the window fails to open, ensure platforms\qwindows.dll is next to pvp.exe.
EOF

echo "==> Creating ${ZIP}..."
rm -f "$ZIP"
(
  cd "${ROOT}/dist"
  zip -r -q "$(basename "$ZIP")" "$(basename "$OUT_DIR")"
)

echo
echo "Done."
echo "  Folder: ${OUT_DIR}"
echo "  Zip:    ${ZIP}"
ls -lh "$ZIP" "$OUT_DIR/pvp.exe"
echo "Send the zip (or the whole folder) to the Windows user."

#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
flutter_bin="${PVP_FLUTTER:-$repo_root/.build/flutter-security-sdk/bin/flutter}"
if [[ ! -x "$flutter_bin" ]]; then flutter_bin="$(command -v flutter)"; fi
"$flutter_bin" --version --machine | python3 -c 'import json,sys; v=json.load(sys.stdin)["dartSdkVersion"].split(" ")[0].split("."); assert tuple(map(int,v[:2])) >= (3,11), "Use Flutter 3.41+ / Dart 3.11+ to avoid GHSA-q739-79rh-vmvp"'
cd "$repo_root/desktop"
"$flutter_bin" pub get --enforce-lockfile
"$flutter_bin" build macos --release --no-pub
cd "$repo_root"
output_dir="${PVP_OUTPUT_DIR:-dist/PVP-macOS-1.0.20}"
mkdir -p "$output_dir"
ditto desktop/build/macos/Build/Products/Release/PVP.app "$output_dir/PVP.app"
if [[ -n "${PVP_SIGNING_IDENTITY:-}" ]]; then
  for framework in "$output_dir"/PVP.app/Contents/Frameworks/*.framework; do
    codesign --force --options runtime --timestamp --sign "$PVP_SIGNING_IDENTITY" "$framework"
  done
  codesign --force --options runtime --timestamp --entitlements desktop/macos/Runner/Release.entitlements \
    --sign "$PVP_SIGNING_IDENTITY" "$output_dir/PVP.app"
fi
codesign --verify --deep --strict "$output_dir/PVP.app"
ditto -c -k --sequesterRsrc --keepParent "$output_dir/PVP.app" "$output_dir.zip"
printf 'Built %s/%s/PVP.app\n' "$repo_root" "$output_dir"

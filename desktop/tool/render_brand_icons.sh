#!/bin/sh
set -eu
# Original PVP doorway artwork; no third-party image/font assets.
# Requires librsvg's rsvg-convert; run from any working directory.
desktop_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
asset_dir="$desktop_dir/macos/Runner/Assets.xcassets/AppIcon.appiconset"
for size in 16 32 64 128 256 512 1024; do
  rsvg-convert -w "$size" -h "$size" "$desktop_dir/assets/brand/pvp-icon.svg" -o "$asset_dir/app_icon_$size.png"
done

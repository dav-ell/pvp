# PVP room identity

Original doorway artwork for the room-first PVP interface. PVP remains the product name.

- pvp-icon.svg: amber app/Dock icon with ink linework.
- pvp-menu.svg: monochrome template artwork for native menu-bar use.
- Flutter's Brand and AppKit's roomStatusImage() draw this same 24-unit doorway geometry without remote assets.

Rebuild all macOS AppIcon PNG sizes with sh desktop/tool/render_brand_icons.sh from the repository root. The generator requires local rsvg-convert and makes no network requests.

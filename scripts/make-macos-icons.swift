import AppKit
import Foundation

// Use the same palette as the browser and Flutter. Paths are relative to repo root.
let tokenData = try Data(contentsOf: URL(fileURLWithPath: "packages/pvp-ui/brand-tokens.json"))
let tokens = try JSONSerialization.jsonObject(with: tokenData) as! [String: Any]
let colors = tokens["colors"] as! [String: String]
func color(_ name: String) -> NSColor {
  let value = UInt32(colors[name]!.dropFirst(), radix: 16)!
  return NSColor(calibratedRed: CGFloat((value >> 16) & 255) / 255,
    green: CGFloat((value >> 8) & 255) / 255, blue: CGFloat(value & 255) / 255, alpha: 1)
}
let target = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "desktop/macos/Runner/Assets.xcassets/AppIcon.appiconset"
for size in [16, 32, 64, 128, 256, 512, 1024] {
  let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
  bitmap.size = NSSize(width: size, height: size)
  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
  let context = NSGraphicsContext.current!.cgContext
  context.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
  color("accent").setFill()
  NSBezierPath(roundedRect: NSRect(x: 64, y: 64, width: 896, height: 896), xRadius: 206, yRadius: 206).fill()
  color("ink").setStroke()
  let frame = NSBezierPath(roundedRect: NSRect(x: 250, y: 230, width: 278, height: 564), xRadius: 18, yRadius: 18)
  frame.lineWidth = 38; frame.stroke()
  let door = NSBezierPath()
  door.move(to: NSPoint(x: 528,y: 230)); door.line(to: NSPoint(x: 780,y: 320))
  door.line(to: NSPoint(x: 780,y: 704)); door.line(to: NSPoint(x: 528,y: 794)); door.close()
  color("accent").setFill(); door.fill()
  door.lineWidth = 38; door.lineJoinStyle = .round; door.stroke()
  color("ink").setFill()
  NSBezierPath(ovalIn: NSRect(x: 628,y: 493,width: 28,height: 38)).fill()
  NSGraphicsContext.restoreGraphicsState()
  try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "\(target)/app_icon_\(size).png"))
}

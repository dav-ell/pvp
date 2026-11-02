import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  override func applicationDidFinishLaunching(_ notification: Notification) {
    super.applicationDidFinishLaunching(notification)
    let event = NSAppleEventManager.shared().currentAppleEvent
    if event?.eventID == kAEOpenApplication && event?.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem {
      MainFlutterWindow.host?.hideWindow()
    }
  }
  override func application(_ application: NSApplication, open urls: [URL]) {
    guard let url = urls.last(where: { $0.scheme == "pvp" && $0.host == "meeting" && $0.absoluteString.count < 4096 }) else { return }
    MainFlutterWindow.pendingMeetingLink = url.absoluteString
    MainFlutterWindow.host?.acceptMeetingLink(url.absoluteString)
  }

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return false
  }

  override func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    return MainFlutterWindow.host?.requestQuit() ?? .terminateNow
  }

  override func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
    MainFlutterWindow.host?.showWindow()
    return true
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }
}

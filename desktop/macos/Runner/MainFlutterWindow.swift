import Cocoa
import FlutterMacOS
import Security
import ServiceManagement
import UserNotifications
import Network
import AVFoundation
import WebRTC
import flutter_webrtc
import UniformTypeIdentifiers

// Keep only a scalar level; audio samples are never retained by the meter.
final class MicrophoneMeter: NSObject, RTCAudioRenderer {
  private let lock = NSLock()
  private var peak: Double = 0
  private var sampledAt: TimeInterval = 0
  func render(pcmBuffer: AVAudioPCMBuffer) {
    guard let channels = pcmBuffer.int16ChannelData else { return }
    var maximum: Double = 0
    for channel in 0..<Int(pcmBuffer.format.channelCount) {
      for frame in 0..<Int(pcmBuffer.frameLength) {
        maximum = max(maximum, abs(Double(channels[channel][frame])) / 32768)
      }
    }
    lock.lock()
    peak = max(peak, maximum); sampledAt = ProcessInfo.processInfo.systemUptime
    lock.unlock()
  }
  func read() -> [String: Any] {
    lock.lock(); defer { lock.unlock() }
    let fresh = sampledAt > 0 && ProcessInfo.processInfo.systemUptime - sampledAt < 1
    let value = fresh ? peak : 0
    peak = 0
    return ["level": value, "receivingSamples": fresh]
  }
}

#if DEBUG
// Replace captured samples with a controlled tone for local integration tests.
// This fixture is absent from distributed release builds.
final class AudioTestTone: NSObject, ExternalAudioProcessingDelegate {
  private var phase: Double = 0
  private var rate: Double = 48000
  func audioProcessingInitialize(withSampleRate sampleRateHz: Int, channels: Int) { rate = Double(sampleRateHz) }
  func audioProcessingProcess(_ buffer: RTCAudioBuffer) {
    for frame in 0..<buffer.frames {
      let value = Float(sin(phase) * 4900)
      phase += 2 * .pi * 440 / rate
      if phase > 2 * .pi { phase -= 2 * .pi }
      for channel in 0..<buffer.channels { buffer.rawBuffer(forChannel: channel)[frame] = value }
    }
  }
  func audioProcessingRelease() { phase = 0 }
}
#endif

class MainFlutterWindow: NSWindow {
  static var host: PvpHost?
  static var pendingMeetingLink: String?
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)

    title = "PVP"
    minSize = NSSize(width: 860, height: 650)
    setContentSize(NSSize(width: 1120, height: 780))
    center()
    backgroundColor = NSColor(calibratedRed: 0.97, green: 0.96, blue: 0.94, alpha: 1)
    titlebarAppearsTransparent = true
    isReleasedWhenClosed = false
    MainFlutterWindow.host = PvpHost(window: self, messenger: flutterViewController.engine.binaryMessenger)

    super.awakeFromNib()
  }
}

// The Flutter engine stays alive when the window is hidden. AppKit owns the
// menu-bar item, Keychain, local notifications, and login-item registration.
final class PvpHost: NSObject, NSWindowDelegate, UNUserNotificationCenterDelegate {
  private weak var window: NSWindow?
  private let channel: FlutterMethodChannel
  private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
  private var state: [String: Any] = [:]
  private var speakingSound: NSSound?
  private var ringingID: String?
  private var ringingTimer: Timer?
  private var awaitingQuit = false
  private let monitor = NWPathMonitor()
  private var listeningActivity: NSObjectProtocol?
  private let audioQueue = DispatchQueue(label: "space.lopixel.pvp.audio")
  private let microphoneMeter = MicrophoneMeter()
  private var metering = false
  private var selectedMicrophoneID = "default"
  private var selectedMicrophoneName = ""
#if DEBUG
  private var audioTestTone: AudioTestTone?
#endif

  init(window: NSWindow, messenger: FlutterBinaryMessenger) {
    self.window = window
    channel = FlutterMethodChannel(name: "space.lopixel.pvp/host", binaryMessenger: messenger)
    super.init()
    window.delegate = self
    item.button?.image = roomStatusImage()
    item.button?.toolTip = "PVP — a room for your people"
    channel.setMethodCallHandler { [weak self] call, result in self?.handle(call, result) }
    UNUserNotificationCenter.current().delegate = self
    let answer = UNNotificationAction(identifier: "answer", title: "Answer", options: [.foreground])
    let decline = UNNotificationAction(identifier: "decline", title: "Decline", options: [])
    UNUserNotificationCenter.current().setNotificationCategories([
      UNNotificationCategory(identifier: "incoming-call", actions: [answer, decline], intentIdentifiers: [], options: [])
    ])
    let center = NSWorkspace.shared.notificationCenter
    center.addObserver(self, selector: #selector(sleeping), name: NSWorkspace.willSleepNotification, object: nil)
    center.addObserver(self, selector: #selector(waking), name: NSWorkspace.didWakeNotification, object: nil)
    monitor.pathUpdateHandler = { [weak self] path in
      DispatchQueue.main.async { self?.event("network", ["available": path.status == .satisfied]) }
    }
    monitor.start(queue: DispatchQueue(label: "space.lopixel.pvp.network"))
    rebuildMenu()
  }

  private func handle(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
    let args = call.arguments as? [String: Any] ?? [:]
    switch call.method {
    case "takeMeetingLink":
      let link = MainFlutterWindow.pendingMeetingLink
      MainFlutterWindow.pendingMeetingLink = nil
      result(link)
    case "readSession":
      let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "space.lopixel.pvp.session", kSecAttrAccount as String: call.arguments as? String ?? "",
        kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
      var data: CFTypeRef?
      let code = SecItemCopyMatching(query as CFDictionary, &data)
      if code == errSecItemNotFound { result(nil) }
      else if code == errSecSuccess, let bytes = data as? Data { result(String(data: bytes, encoding: .utf8)) }
      else { result(FlutterError(code: "keychain", message: "Could not read your saved sign-in (\(code)).", details: nil)) }
    case "saveSession":
      let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "space.lopixel.pvp.session", kSecAttrAccount as String: args["origin"] as? String ?? ""]
      if let session = args["session"] as? String {
        let values = [kSecValueData as String: Data(session.utf8)]
        var code = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if code == errSecItemNotFound {
          var add = query
          add.merge(values) { _, new in new }
          add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
          code = SecItemAdd(add as CFDictionary, nil)
        }
        result(code == errSecSuccess ? nil : FlutterError(code: "keychain", message: "Could not save your sign-in (\(code)).", details: nil))
      } else {
        let code = SecItemDelete(query as CFDictionary)
        result(code == errSecSuccess || code == errSecItemNotFound ? nil : FlutterError(code: "keychain", message: "Could not clear your saved sign-in.", details: nil))
      }
    case "readPreferences": result(UserDefaults.standard.string(forKey: "pvp." + (call.arguments as? String ?? "")))
    case "savePreferences":
      UserDefaults.standard.set(args["value"] as? String, forKey: "pvp." + (args["key"] as? String ?? ""))
      result(nil)
    case "sync":
      state = args
      if args["online"] as? Bool == true, listeningActivity == nil {
        listeningActivity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep, reason: "Receive incoming PVP calls")
      } else if args["online"] as? Bool != true, let activity = listeningActivity {
        ProcessInfo.processInfo.endActivity(activity); listeningActivity = nil
      }
      rebuildMenu(); result(nil)
    case "diagnostics": result(["windowVisible": window?.isVisible ?? false, "menuBarPresent": item.button != nil, "online": state["online"] as? Bool ?? false])
    case "pickChatAttachment":
      let panel = NSOpenPanel()
      panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
      panel.title = "Share an image or file in this call"
      panel.begin { response in
        guard response == .OK, let url = panel.url else { result(nil); return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
          let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
          guard values.isRegularFile == true, let size = values.fileSize, size > 0, size <= 104857600 else {
            result(FlutterError(code: "attachment", message: "Choose a regular file between 1 byte and 100 MiB.", details: nil)); return
          }
          let handle = try FileHandle(forReadingFrom: url)
          defer { try? handle.close() }
          let data = try handle.read(upToCount: 104857601) ?? Data()
          guard !data.isEmpty, data.count <= 104857600 else { result(FlutterError(code: "attachment", message: "File exceeds 100 MiB.", details: nil)); return }
          result(["name": url.lastPathComponent, "bytes": FlutterStandardTypedData(bytes: data)])
        } catch { result(FlutterError(code: "attachment", message: "Could not read this file.", details: nil)) }
      }
    case "saveChatAttachment":
      guard let args = call.arguments as? [String: Any], let name = args["name"] as? String,
        !name.isEmpty, name.count <= 200, !name.contains("/"), !name.contains("\\"),
        let bytes = args["bytes"] as? FlutterStandardTypedData, bytes.data.count <= 104857600 else {
        result(FlutterError(code: "attachment", message: "Invalid attachment.", details: nil)); return
      }
      let panel = NSSavePanel(); panel.nameFieldStringValue = name; panel.title = "Save meeting attachment"
      panel.begin { response in
        guard response == .OK, let url = panel.url else { result(false); return }
        do { try bytes.data.write(to: url, options: .atomic); result(true) }
        catch { result(FlutterError(code: "attachment", message: "Could not save this file.", details: nil)) }
      }
    case "saveConnectionReport":
      guard let json = call.arguments as? String, let data = json.data(using: .utf8), data.count <= 262144,
        let report = try? JSONSerialization.jsonObject(with: data) as? [String: Any], [1, 2].contains(report["schemaVersion"] as? Int ?? 0) else {
        result(FlutterError(code: "report", message: "Invalid connection report.", details: nil)); return
      }
      let panel = NSSavePanel()
      panel.allowedContentTypes = [.json]
      panel.nameFieldStringValue = "PVP-connection.json"
      panel.title = "Save connection report"
      panel.message = "This report contains network addresses. Share it only when you intend to."
      panel.begin { response in
        guard response == .OK, let url = panel.url else { result(false); return }
        do { try data.write(to: url, options: .atomic); result(true) }
        catch { result(FlutterError(code: "report", message: "Could not save the connection report.", details: nil)) }
      }
    case "show": showWindow(); result(nil)
    case "hide": hideWindow(); result(nil)
    case "speakingAllowed":
      speakingSound = NSSound(named: "Glass")?.copy() as? NSSound
      speakingSound?.volume = 0.25
      speakingSound?.play()
      result(nil)
    case "incoming":
      stopRinging()
      ringingID = args["call_id"] as? String
      if args["sound"] as? Bool ?? true {
        NSSound(named: "Glass")?.play()
        ringingTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { _ in NSSound(named: "Glass")?.play() }
      }
      let content = UNMutableNotificationContent()
      content.title = "\(args["name"] as? String ?? "A friend") is calling"
      content.body = "Answer to join the PVP voice call. Camera optional."
      content.categoryIdentifier = "incoming-call"
      content.userInfo = ["call_id": ringingID ?? ""]
      if args["sound"] as? Bool ?? true { content.sound = .default }
      UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: ringingID ?? "incoming", content: content, trigger: nil))
      // Present the incoming-call window even when alerts were denied.
      showWindow(); NSApp.requestUserAttention(.criticalRequest)
      result(nil)
    case "stopRinging": stopRinging(); result(nil)
    case "notifications":
      UNUserNotificationCenter.current().getNotificationSettings { settings in
        DispatchQueue.main.async { result(settings.authorizationStatus == .authorized ? "enabled" : settings.authorizationStatus == .notDetermined ? "notRequested" : "denied") }
      }
    case "enableNotifications":
      UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
        DispatchQueue.main.async { result(error == nil ? granted : FlutterError(code: "notifications", message: error?.localizedDescription, details: nil)) }
      }
    case "screenCapturePermission":
      result(CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess())
    case "openScreenPrivacy":
      if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture") { NSWorkspace.shared.open(url) }; result(nil)
    case "capturePermissionStatus":
      result(["microphone": AVCaptureDevice.authorizationStatus(for: .audio).rawValue, "camera": AVCaptureDevice.authorizationStatus(for: .video).rawValue])
    case "capturePermissions":
      requestAccess(.audio) { [weak self] audio in
        guard audio else { DispatchQueue.main.async { result(false) }; return }
        if args["camera"] as? Bool == false { DispatchQueue.main.async { result(true) } }
        else { self?.requestAccess(.video) { video in DispatchQueue.main.async { result(video) } } }
      }
    case "selectAudioDevice":
      guard let adm = FlutterWebRTCPlugin.sharedSingleton()?.peerConnectionFactory?.audioDeviceModule else {
        result(FlutterError(code: "audio", message: "The audio engine is unavailable.", details: nil)); return
      }
      let input = args["kind"] as? String == "audioinput"
      let id = args["id"] as? String ?? ""
      let devices = input ? adm.inputDevices : adm.outputDevices
      let device = id.isEmpty ? RTCIODevice.defaultDevice(with: input ? .input : .output) : devices.first { $0.deviceId == id }
      guard let device = device else {
        result(FlutterError(code: "audio", message: "That audio device is unavailable. Select System default or another device.", details: nil)); return
      }
      audioQueue.async {
        // In pinned WebRTC-SDK 150.7871.01, trySet* returns the C++ integer
        // status as BOOL: 0 is success. AudioEngine's selected-device getters
        // are also unimplemented. Validate membership above and correct the
        // setter result rather than consulting those getters.
        let changed = input ? !adm.trySetInputDevice(device) : !adm.trySetOutputDevice(device)
        DispatchQueue.main.async {
          if changed && input { self.selectedMicrophoneID = device.deviceId; self.selectedMicrophoneName = device.name }
          result(changed ? device.name : FlutterError(code: "audio", message: "Could not open that audio device. Choose another device.", details: nil))
        }
      }
    case "setEchoCancellation":
      guard let id = args["trackId"] as? String, let enabled = args["enabled"] as? Bool,
        let track = FlutterWebRTCPlugin.sharedSingleton()?.track(forId: id, peerConnectionId: nil) as? RTCAudioTrack else {
        result(FlutterError(code: "audio", message: "The microphone is no longer available.", details: nil)); return
      }
      audioQueue.async {
        // Keep noise suppression and gain control enabled. Automatic mode uses
        // WebRTC software processing when the platform cannot provide an effect.
        let options = RTCAudioProcessingOptions(echoCancellation: enabled,
          noiseSuppression: true, autoGainControl: true, highPassFilter: true)
        let applied = track.setAudioProcessingOptions(options)
        DispatchQueue.main.async {
          result(applied.isSuccess ? nil : FlutterError(code: "audio",
            message: "Could not change echo cancellation: \(applied.message)", details: nil))
        }
      }
    case "startAudioMonitor":
      guard let adm = FlutterWebRTCPlugin.sharedSingleton()?.peerConnectionFactory?.audioDeviceModule else {
        result(FlutterError(code: "audio", message: "The microphone is unavailable.", details: nil)); return
      }
      if !metering { AudioManager.sharedInstance().addLocalAudioRenderer(microphoneMeter); metering = true }
      audioQueue.async {
        let code = adm.initAndStartRecording()
        DispatchQueue.main.async { result(code == 0 ? nil : FlutterError(code: "audio", message: "The microphone could not start. Select another input in Call settings.", details: nil)) }
      }
    case "stopAudioMonitor":
      if metering { AudioManager.sharedInstance().removeLocalAudioRenderer(microphoneMeter); metering = false }
      let adm = FlutterWebRTCPlugin.sharedSingleton()?.peerConnectionFactory?.audioDeviceModule
      audioQueue.async { _ = adm?.stopRecording(); DispatchQueue.main.async { result(nil) } }
    case "microphoneStatus":
      var status = microphoneMeter.read()
      if let adm = FlutterWebRTCPlugin.sharedSingleton()?.peerConnectionFactory?.audioDeviceModule {
        status["recording"] = adm.isRecording
        status["deviceMuted"] = adm.isMicrophoneMuted
        status["deviceName"] = selectedMicrophoneID == "default" ? adm.inputDevices.first(where: { $0.isDefault })?.name ?? "System default" : selectedMicrophoneName
        status["deviceDefault"] = selectedMicrophoneID == "default"
        status["deviceId"] = selectedMicrophoneID
      }
      result(status)
#if DEBUG
    case "testAudioTone":
      if call.arguments as? Bool == true {
        if audioTestTone == nil {
          let tone = AudioTestTone(); audioTestTone = tone
          AudioManager.sharedInstance().capturePostProcessingAdapter.addProcessing(tone)
        }
      } else if let tone = audioTestTone {
        AudioManager.sharedInstance().capturePostProcessingAdapter.removeProcessing(tone)
        audioTestTone = nil
      }
      result(nil)
#endif
    case "loginStatus": result(loginStatus())
    case "setLogin":
      do {
        if call.arguments as? Bool ?? false { try SMAppService.mainApp.register() }
        else { try SMAppService.mainApp.unregister() }
        result(loginStatus())
      } catch { result(FlutterError(code: "login", message: error.localizedDescription, details: nil)) }
    case "openLoginSettings": SMAppService.openSystemSettingsLoginItems(); result(nil)
    case "openNotificationSettings":
      if let url = URL(string: "x-apple.systempreferences:com.apple.preference.notifications") { NSWorkspace.shared.open(url) }
      result(nil)
    case "openPrivacy":
      let section = call.arguments as? String == "camera" ? "Privacy_Camera" : "Privacy_Microphone"
      if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?\(section)") { NSWorkspace.shared.open(url) }
      result(nil)
    case "quit": NSApp.terminate(nil); result(nil)
    case "quitComplete": result(nil); NSApp.reply(toApplicationShouldTerminate: true)
    default: result(FlutterMethodNotImplemented)
    }
  }

  private func requestAccess(_ type: AVMediaType, completion: @escaping (Bool) -> Void) {
    switch AVCaptureDevice.authorizationStatus(for: type) {
    case .authorized: completion(true)
    case .notDetermined: AVCaptureDevice.requestAccess(for: type, completionHandler: completion)
    default: completion(false)
    }
  }
  private func loginStatus() -> String {
    switch SMAppService.mainApp.status {
    case .enabled: return "enabled"
    case .requiresApproval: return "requiresApproval"
    case .notFound: return "notFound"
    default: return "disabled"
    }
  }
  func acceptMeetingLink(_ url: String) {
    MainFlutterWindow.pendingMeetingLink = url
    showWindow()
    event("meeting-link", ["url": url])
  }

  func event(_ name: String, _ args: [String: Any] = [:]) { channel.invokeMethod(name, arguments: args) }
  func showWindow() {
    NSApp.setActivationPolicy(.regular)
    window?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }
  func hideWindow() { window?.orderOut(nil); NSApp.setActivationPolicy(.accessory); event("hidden") }
  func windowShouldClose(_ sender: NSWindow) -> Bool { hideWindow(); return false }
  @objc private func sleeping() { event("sleep") }
  @objc private func waking() { event("wake") }
  @objc private func openApp() { showWindow() }
  @objc private func preferences() { showWindow(); event("settings") }
  @objc private func answer() { showWindow(); event("answer", ["call_id": ringingID ?? ""]) }
  @objc private func decline() { event("decline", ["call_id": ringingID ?? ""]) }
  @objc private func callFriend(_ sender: NSMenuItem) { showWindow(); event("call", ["peer_id": sender.representedObject as? String ?? ""]) }
  @objc private func hangup() { event("hangup") }
  @objc private func quit() { NSApp.terminate(nil) }
  @discardableResult private func menuEntry(_ menu: NSMenu, _ title: String, _ action: Selector?, key: String = "") -> NSMenuItem {
    let entry = NSMenuItem(title: title, action: action, keyEquivalent: key)
    entry.target = self; menu.addItem(entry); return entry
  }
  private func rebuildMenu() {
    let menu = NSMenu()
    menu.autoenablesItems = false
    menuEntry(menu, "PVP · \(state["name"] as? String ?? "Sign in")", #selector(openApp))
    menuEntry(menu, state["online"] as? Bool == true ? "Ready for calls" : "Connecting / signed out", nil)
    if state["incoming"] as? Bool == true {
      menu.addItem(.separator()); menuEntry(menu, "Answer call", #selector(answer)); menuEntry(menu, "Decline", #selector(decline))
    } else if state["busy"] as? Bool == true {
      menu.addItem(.separator()); menuEntry(menu, "End call", #selector(hangup))
    } else if let friends = state["friends"] as? [[String: Any]], !friends.isEmpty {
      menu.addItem(.separator())
      for friend in friends.prefix(20) {
        let entry = menuEntry(menu, "\(friend["online"] as? Bool == true ? "●" : "○")  \(friend["name"] as? String ?? "Friend")", #selector(callFriend))
        entry.representedObject = friend["id"]; entry.isEnabled = state["online"] as? Bool == true
      }
    }
    menu.addItem(.separator()); menuEntry(menu, "Open PVP", #selector(openApp), key: "o")
    menuEntry(menu, "Settings…", #selector(preferences), key: ",")
    menu.addItem(.separator()); menuEntry(menu, "Quit PVP", #selector(quit), key: "q")
    item.menu = menu
    item.button?.image = state["incoming"] as? Bool == true
      ? NSImage(systemSymbolName: "phone.badge.waveform.fill", accessibilityDescription: "Incoming PVP call")
      : roomStatusImage()
  }
  // Original doorway mark, drawn as a template so macOS supplies menu-bar contrast.
  private func roomStatusImage() -> NSImage {
    let image = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { _ in
      let transform = NSAffineTransform()
      transform.scale(by: 0.75)
      transform.concat()
      NSColor.black.setStroke()
      let frame = NSBezierPath()
      frame.move(to: NSPoint(x: 13, y: 3))
      frame.line(to: NSPoint(x: 5, y: 3))
      frame.curve(to: NSPoint(x: 3, y: 5), controlPoint1: NSPoint(x: 3.9, y: 3), controlPoint2: NSPoint(x: 3, y: 3.9))
      frame.line(to: NSPoint(x: 3, y: 19))
      frame.curve(to: NSPoint(x: 5, y: 21), controlPoint1: NSPoint(x: 3, y: 20.1), controlPoint2: NSPoint(x: 3.9, y: 21))
      frame.line(to: NSPoint(x: 13, y: 21))
      frame.move(to: NSPoint(x: 13, y: 3))
      frame.line(to: NSPoint(x: 13, y: 21))
      frame.line(to: NSPoint(x: 21, y: 18))
      frame.line(to: NSPoint(x: 21, y: 6))
      frame.close()
      frame.lineWidth = 1.65
      frame.lineCapStyle = .round
      frame.lineJoinStyle = .round
      frame.stroke()
      NSColor.black.setFill()
      NSBezierPath(ovalIn: NSRect(x: 15.8, y: 11.3, width: 1.4, height: 1.4)).fill()
      return true
    }
    image.isTemplate = true
    image.accessibilityDescription = "PVP"
    return image
  }

  private func stopRinging() {
    ringingTimer?.invalidate(); ringingTimer = nil
    NSSound(named: "Glass")?.stop()
    if let id = ringingID {
      UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [id])
      UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [id])
    }
    ringingID = nil
  }
  func requestQuit() -> NSApplication.TerminateReply {
    if awaitingQuit { return .terminateNow }
    awaitingQuit = true; stopRinging(); event("quit")
    DispatchQueue.main.asyncAfter(deadline: .now() + 3) { NSApp.reply(toApplicationShouldTerminate: true) }
    return .terminateLater
  }
  func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    completionHandler([.banner])
  }
  func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
    let id = response.notification.request.content.userInfo["call_id"] as? String ?? ""
    DispatchQueue.main.async { [weak self] in
      if response.actionIdentifier != "decline" { self?.showWindow() }
      self?.event(response.actionIdentifier == "decline" ? "decline" : response.actionIdentifier == "answer" ? "answer" : "open", ["call_id": id])
      completionHandler()
    }
  }
}

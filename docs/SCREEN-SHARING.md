# Screen sharing

PVP 1.0.4 adds screen and window sharing to the Mac app. The corresponding browser client adds a Share screen button. During a connected call, select Share screen, choose a source, and use Stop sharing to return to the camera. The camera control pauses/resumes the outgoing screen video while sharing.

Screen video replaces the outgoing camera track on the existing WebRTC sender. There is no additional signaling protocol, peer connection, media server, or upload endpoint. Existing native receivers receive the replacement video through their normal video renderer. DTLS-SRTP encryption and direct-only ICE policy remain in force. Both clients preserve microphone routing/mute and the camera's previous on/off state. Sharing sends screen video and the existing microphone, without computer/system audio.

The browser uses its platform capture picker and restores the camera when the browser fires the display track's ended event. Mac lists the actual screen/window sources exposed by flutter_webrtc, requests Screen Recording permission only after a Share screen click, and monitors whether the chosen source disappears. Mac requires Screen Recording permission in System Settings → Privacy & Security; macOS may require reopening PVP after granting it. Use PVP's Stop sharing control to end native capture. The pinned native plugin does not deliver track-ended events for all operating-system capture termination paths, so automatic recovery from the macOS system stop control has not been verified.

Hangup, logout, and normal call teardown release screen capture. A late capture result after hangup is immediately disposed. Sender replacement failures restore the previous video where possible; failure to restore after stop ends the call with an error. Choosing Cancel leaves the current call unchanged. Source/window titles are shown locally and are not added to connection-inspector exports.

## Verification

- Browser suite: real canvas video transmitted through real WebRTC; recipient pixel color and dimensions checked; same peer connection and microphone track preserved; inbound audio energy continues rising. Tests cover explicit stop, browser ended event, previously disabled camera, picker cancellation, and hangup during a pending picker.
- Mac unit suite: video replacement, muted microphone preservation, restoration of a disabled camera, capture disposal, and hangup during a pending picker.
- Signed Mac integration: browser-to-Mac sharing receives 960×540 screen video, then restores 640×360 camera video on the same native peer connection; existing direct-path, cipher, verification-code, incoming/outgoing and native interoperability checks pass.
- Flutter analysis passes; signed universal Mac app builds and verifies.

Native physical Screen Recording capture and outbound hardware microphone were not exercised automatically. Browser capture tests use synthetic source video to avoid recording unrelated desktop content.

## Release status

Package: `dist/PVP-macOS-1.0.4.zip`, development-signed universal macOS app. Prior app packages remain available. This package is not notarized.

Production and the installed Mac app were subsequently upgraded to signaling 0.3.4 and PVP 1.0.5+6, which include screen sharing and group calls. The Mac app was reopened and its connection to the production service verified. Previous packages and installation/database backups are retained. See the [current release manifest](group-calls-release.json) for deployment and rollback details.

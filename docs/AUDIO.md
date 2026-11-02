# Audio update — October 4, 2026

This audio release shipped Flutter 1.0.2+3 and signaling/browser 0.3.1. The later [Connection inspector release](CONNECTION-INSPECTOR.md) retains these fixes in Flutter 1.0.3 and signaling/browser 0.3.2. Accounts, friendships and the authenticated calling protocol are retained. Call media still travels directly between clients using DTLS-SRTP.

## Checking a one-way audio call

1. On the person whose voice is missing, enable PVP under **System Settings → Privacy & Security → Microphone**, then reopen the app. Browser users should allow microphone access for the site.
2. Open **Call settings**, unmute the microphone and select the intended input. Speak and check the microphone activity meter. Try **System default** or the Mac's built-in microphone if the meter stays flat.
3. On the receiving browser, click **Enable your friend's audio** if that button appears. Check the receiving device's speaker selection and volume.

The microphone meter checks local capture; it does not prove the friend hears audio. Confirm that with the friend. The meter keeps only a scalar activity level, without recording audio or uploading a separate diagnostic stream.

**Echo cancellation** is on by default on Mac and web, including existing accounts without a saved choice. It reduces speaker playback picked up by the local microphone. Toggle it in **Settings → Camera & audio** on Mac, **Settings → Camera & microphone** on web, or the call controls. The choice is saved per account on this device and applies immediately to preview, direct calls, voice rooms, and meetings while preserving the call and microphone mute state. Each participant controls their own microphone processing; the person using speakers should leave it on. Noise suppression and automatic gain control remain enabled.

On Mac, the pinned Flutter plugin does not apply audio-processing changes through `MediaStreamTrack.applyConstraints`. PVP sets the captured local track's processing options explicitly using the WebRTC SDK's runtime API, at capture and when toggled. See the [SDK's local-track processing API](https://github.com/webrtc-sdk/webrtc/blob/m150_release/sdk/objc/api/peerconnection/RTCAudioTrack.h). Browser changes first try `applyConstraints` and check the reported setting. When live reconfiguration is unavailable, PVP captures a replacement microphone and swaps it into each connected peer, retaining camera/screen tracks, connections and mute state. Failed replacement restores the previous senders and stops the rejected capture. Rejected changes restore the previous choice. Automated coverage checks preferences, capture/recapture, mute preservation, direct/group calls and browser processing settings; audible echo and the reported popping still require a physical speaker/microphone check.

## Changes

- Native audio-device enumeration is initialized before the first call. Microphone and speaker selection explicitly use the native audio device module, including restoring System default. Changing the microphone during a call retains the audio track and its mute state.
- The pinned Darwin plugin skips its `audio.deviceId` handling on macOS. The pinned SDK's `trySetInputDevice` / `trySetOutputDevice` methods expose the underlying integer status through a Boolean return value, while selected-device getters are unsupported by its AudioEngine backend. The host validates device membership and interprets the setters' result for this pinned SDK. Reassess this adapter when upgrading WebRTC-SDK.
- Each new call resets track mute state. Missing microphone tracks, denied permissions and audio-engine startup failures produce an actionable error. Preview starts microphone capture deliberately, and preview/call cleanup stops it.
- Native and browser settings show microphone activity. Both provide microphone selection during a call.
- Browser remote tracks are merged into a stable stream. Blocked remote audio playback has an explicit retry button. If replacing capture tracks partially fails, already-replaced senders are restored before the rejected capture is stopped.
- A delayed initial browser session failure preserves credentials being typed. Session guards still prevent a stale initial response from undoing a completed sign-in.

Upstream references: [Darwin capture handling](https://github.com/flutter-webrtc/flutter-webrtc/blob/main/common/darwin/Classes/FlutterRTCMediaStream.m), [audio device module wrapper](https://github.com/webrtc-sdk/webrtc/blob/m150_release/sdk/objc/api/peerconnection/RTCAudioDeviceModule.mm), and [AudioEngine device implementation](https://github.com/webrtc-sdk/webrtc/blob/m150_release/modules/audio_device/audio_engine_device.mm). The release pins flutter_webrtc 1.6.2+hotfix.3 and WebRTC-SDK 150.7871.01.

## Validation and limits

- All 14 local browser/security checks and all five production browser scenarios passed. Audio tests measure increasing inbound audio energy in both directions, silence while muted, resumed sound after unmute, input switching, partial track-replacement rollback and autoplay recovery. Browser tracks are generated test audio/video.
- Flutter analysis and all seven unit/widget checks passed, including microphone routing and preference rollback on failure. The Rust launcher passes `cargo check --locked --bin pvp`.
- Native integration passed native/browser connections in both directions, received audio/video, hidden-window ringing, cleanup, and native–native DTLS. This suite injects empty native capture streams; it does not validate physical microphone transmission.
- The optional native outbound-audio test stopped at macOS's permission preflight: microphone access was denied. Physical native capture, its meter, and outbound sound remain unverified until permission is enabled. The debug-only tone fixture is absent from the release binary.
- Production SQLite integrity is `ok`; the four exact verification accounts were removed after testing. Existing game and relay services remain active.

To run the optional native audio check after granting permission:

```sh
PVP_TEST_AUDIO=1 npm run test:native
```

## Audio-only browser playback

A camera-off browser call could receive encrypted audio packets and report audio energy while remaining silent. The remote media stream also contained a negotiated camera track that had never produced a frame. Both tracks were attached to one video element; in the reproduced Chromium case it stayed at `readyState=0` and `currentTime=0` until the camera was enabled. Packet reception alone therefore did not prove playback had started. This matches the browser's [documented first-video-frame behavior](https://issues.chromium.org/issues/41371147).

The source fix uses an audio-only playback element for each remote peer in meetings, group calls and direct calls. The video element stays muted to avoid duplicate sound. Camera toggles retain the audio element and microphone tracks; leaving disposes the playback elements. Autoplay denial still shows the existing explicit audio retry action, including after an unsuccessful retry.

The guest integration now uses normal Chromium autoplay policy and requires received audio energy plus an advancing, unmuted playback clock before either camera is enabled. It also covers camera on/off, retry after autoplay denial and audio cleanup on leave. Direct-call coverage checks audio playback before video opt-in. The new clock assertion failed against the previous implementation, despite its incoming audio packets, and passes with the separate audio sink. This correction is included in the 0.3.20 mobile meeting browser release. See [mobile release evidence](mobile-meetings-release.json) for deployment status.

For stable test signing, provide `PVP_TEST_SIGNING_IDENTITY` as the available certificate's SHA-1 and `PVP_TEST_TEAM` as its team ID. The harness generates a temporary signing configuration without changing the project's signing settings. It uses isolated accounts and a controlled debug tone instead of transmitting conversation audio.

## Artifacts and rollback

The universal Mac package is `dist/PVP-macOS-1.0.2.zip`. It is development-signed, hardened and sandboxed, with a verified signature; it is not notarized. Original 1.0.0 and 1.0.1 archives are preserved. The previous installed 1.0.0 app is backed up at `.build/PVP-before-audio-1.0.0-1791119697.app`.

The final server deployment was gated on no active signaling WebSockets. The staged binary passed an unprivileged health, asset and registration preflight before the atomic swap. Protected binary/database backups are `/var/backups/pvp/audio-2026-10-04-1791119548` (original 0.3.0) and `/var/backups/pvp/audio-final-2026-10-04-1791120484` (before the final browser startup fix). Only `pvp-signaling` was restarted.

See [release hashes and validation](audio-release.json). The isolated patched Flutter SDK was used; the global SDK and other Flutter apps were unchanged.

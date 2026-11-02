# Browser data saver

In Settings → Picture & bandwidth, choose independent send and receive video limits. Direct calls also expose these controls under Call settings. Changes apply to active calls and are saved per account on this device.

| Mode | Camera and screen video limit per participant |
| --- | --- |
| Automatic (default) | 128 Kbps when connection hints indicate cellular, metered, data saving, or slow service; otherwise normal quality settings |
| Off | Normal quality settings and any participant-specific limits |
| Low | 400 Kbps |
| Very low | 128 Kbps |
| Minimal | 64 Kbps |
| None | Video transmission paused; audio continues |

Limits cover camera and screen video in direct and group calls. Camera encoders also reduce resolution and frame rate at low limits. Group video forwarding falls back to individual WebRTC streams when limits apply. Participant-specific limits can further reduce the global limit.

Receive limits are requests to the sender and require a compatible PVP browser client. Check the connection inspector for support. Older clients may ignore these requests. Limits are per participant, so group totals grow with the number of connections. Audio, chat, file transfers, signaling, and transport overhead are additional; these modes are not a total-data cap or an offline mode.

Automatic detection uses the browser's optional Network Information API, including cellular type, metered and save-data hints, and slow effective connection types. LTE can report an effective type of `4g`; cellular type takes precedence when available. Browsers may not expose cellular or metered status, especially with tethering. Choose a manual limit in that case. Connection changes reapply automatic limits without overwriting saved choices.

Published October 14, 2026 as browser/signaling 0.3.17 at https://lopixel.space. All 25 server tests and 43 web tests passed. Public HTTPS assets, simulated cellular detection, persisted independent choices, and mobile layout were verified. The native Mac app is unchanged. See [release record](data-saver-release.json) for deployment and rollback details.

# Small-group camera quality

With eight or fewer joined participants, Balanced sends every camera at 480p and up to 24 fps, including quiet or muted participants. High quality targets 720p. Input cameras with lower resolution retain their available detail; the encoder does not invent extra camera detail by upscaling. Browser encoded forwarding, browser direct-video fallback, and native camera senders apply this policy.

The default Balanced group video budget scales from 1.8 Mbps to 600 Kbps per remote attendee, up to 4.2 Mbps at eight attendees. The in-call quality control displays that budget. Forwarded video and native compatibility paths share it, with headroom for encoded frame metadata. Actual usage depends on content, capture frame rate and transport conditions. Audio and transport overhead are additional.

Explicit Data Saver and Custom bandwidth limits remain unchanged. Ordinary one-to-one calls retain their settings. With nine or more attendees, the existing speaker/pin-based small-tile optimization continues; returning to eight raises the camera baseline automatically. Screen sharing retains its separate resolution and frame-rate behavior.

Validation checks decoded browser frames at 480p after microphone mute, eight-person direct fallback, native decoding of all five browser cameras at 480p or better, and the nine-to-eight transition without rejoining. Pure policy tests cover quiet/speaking cameras, actual capture height, the eight-person boundary, High quality, Data Saver and explicit Custom limits. Synthetic local media validates dimensions and transport behavior, not subjective camera detail or WAN capacity.

Concurrent meeting-chat edits were preserved in the shared workspace. The quality-only build snapshot under `.build/group-quality/isolated` excludes that unfinished feature. See [release validation](small-group-quality-release.json) for deployment status and artifact hashes.

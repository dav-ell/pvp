# Guest links and Zoom invitations

The browser home screen lets people create and share a reusable meeting link with only a display name. The native app offers **Continue as guest**, then **Create or share meeting links**. Signing in remains available for friends and direct calls. Creating, previewing, and copying links never starts capture; joining still offers microphone or listen-only entry with the camera off.

Guest-created links admit anyone with the link. The guest creator owns the meeting and can mute, kick, delete it, and appoint registered members as admins through the existing controls. Ownership uses a random HttpOnly session, hashed in the database and kept in the browser or native Keychain. It survives service restarts and refreshes, with the existing 30-day session renewal. Signing out, changing accounts, clearing site data, losing the device, or letting the session expire loses guest host access. Saving the public invitation preserves joining access, not host access. Invitation-only guests retain their existing eight-hour, meeting-scoped sessions and cannot use account endpoints.

**Open more private Zoom** is available before sign-in and within the browser and native app. Paste a numbered Zoom URL, a full invitation, or a meeting ID. The result shows a permanent PVP link, a copy action, a ready-to-send group message, and a separate action to continue to the meeting preview. Nothing is automatically sent.

This creates a separate PVP meeting identified by the Zoom meeting, with encrypted P2P media. It does not connect to Zoom participants or carry their media. Everyone must join through PVP.

## Stable room identity

The server parses and validates the invitation and hashes the versioned identity `pvp:zoom:v1:{realm}:{meeting-number}` with SHA-256. Commercial Zoom hosts share one namespace; Zoom Government has a separate namespace. Changing regional or vanity subdomains, passcodes, tracking parameters, or recurring occurrence IDs does not change the room. The same invitation always produces the same PVP URL on the same PVP service, including across restarts and database restores. Keep the domain and database when migrating the service.

Supported forms include `/j/ID`, numbered `/s/ID`, `/wc/join/ID`, `/wc/ID/join`, `/join?confno=ID`, `zoommtg://` and `zoomus://` join links, bare Zoom hostnames, full invitations with a labeled Meeting ID, and Outlook Safe Links / Google URL wrappers. IDs contain 9–11 digits. The parser bounds input and wrapper depth, validates hostnames and schemes, and rejects ambiguous invitations with different meetings. It never fetches a pasted URL, calls Zoom, or stores the URL, passcode, `zak`, or tracking parameters. Named `/my/` links and registration URLs cannot be reliably matched to a numeric room without Zoom resolution; the UI asks for the numbered join invitation instead of guessing.

Anyone with the Zoom meeting ID or resulting PVP link can enter. Zoom passcodes and waiting rooms are not enforced. The public identity is deliberately deterministic and is not an access secret. Use a regular random PVP meeting link for an unguessable invitation and host controls. Direct P2P shares network addresses between participants and cannot traverse every network. Meetings support 16 concurrent participants. Zoom-linked rosters release seats on departure and service restart; visit records retain the reusable link in each persistent visitor's meeting list.

## Host identity

Zoom-linked rooms have no automatic admin. The first person to paste an invitation receives no ownership or admin powers, even when signed in. A join invitation proves knowledge of the invitation, not Zoom host ownership. These rooms use a non-login service owner with no participant seat.

A future **Connect Zoom / Verify host** flow should use Zoom OAuth with the minimum meeting-read scope, fetch the authorized meeting, and compare its `host_id` to the authorized Zoom user. Only after that verification should PVP bind a host role to a durable PVP identity or guest host capability. Do not infer ownership from a display name, claimed email address, the first visitor, a join URL, or a host URL pasted into the public entry form. Zoom documents the meeting's `host_id` and host-only `start_url` in its [Meetings API](https://developers.zoom.us/docs/api/meetings/).

## Validation

`cargo test --manifest-path signaling/Cargo.toml` covers URL variants, spoofed hosts, malformed and ambiguous invitations, deterministic identity, credential omission, and more than sixteen successive visitors without leaked seats. `npm run test:zoom` covers guest creation and moderation, copying, mobile layouts, signed-in and guest normalization, invalid-link recovery, actual encrypted WebRTC audio, restarts, and listen-only guest entry. The existing guest and recurring meeting suites cover admission and moderation compatibility. Native widget tests cover Zoom entry and copying for signed-out, guest, and account users, plus open admission for guest-created links.

## Publication on October 23, 2026

Signaling/browser 0.3.22 and the signed universal Mac 1.0.20+21 archive are published at [lopixel.space](https://lopixel.space). The option is labeled **Open more private Zoom** in both clients and their sharing messages. All 29 live assets and the complete Mac download match the tested artifacts. Public HTTPS verification passed guest link creation, copying, retained guest host controls, stable Zoom identity, mobile guest admission, two-way encrypted WebRTC audio, and released participant seats.

The upgrade ran with zero signaling connections, retained protected binary/configuration/database rollback backups and an off-VM portable database backup, and preserved existing accounts, friendships, meetings, memberships, roles, and access policies. The exact temporary verification user and two test meetings were removed. Database integrity and foreign keys are verified; all existing services are active. The non-login internal Zoom room owner is the only new persistent system identity. The local installed Mac app was not replaced. See [versions, artifact hashes, validation, and rollback records](guest-links-zoom-release.json).

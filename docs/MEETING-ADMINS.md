# Meeting admins

The creator of a recurring meeting is its permanent owner and automatically an admin. In **Meetings → open the meeting**, use a member's **Make admin** action to appoint another admin. Use **Remove admin** to revoke that role. On Mac these actions are in the member's **Manage** menu. Roles persist across calls, service restarts and database backups/restores.

Admins can **Mute**, **Allow unmute**, and **Kick** other members from the member list or during a call. The Mac call has a Manage menu on participant tiles; the browser has Mute/Kick controls. Only the owner appoints or removes admins, invites additional members, or deletes the link. Nobody can remove, demote or admin-mute the owner. Self-muting still uses the normal microphone control. Admins can moderate other admins; the owner retains control of appointments.

**Mute** disables outgoing microphone tracks and prevents the member from using Unmute. It also disables that member's incoming audio on each updated receiver using the authenticated server-issued roster, independently of the sender's own mute messages. Muting persists across leaving/rejoining and restarts until an admin selects **Allow unmute**. That action only restores permission: the microphone stays off until the member chooses Unmute. Creating/opening links still never starts capture automatically.

**Kick** immediately removes the member from the live call and the recurring meeting's approved roster. Remaining clients close their peer links to that person, and browser video publishers rotate their media keys. The server denies subsequent joins and signaling. The owner must send a new membership invitation before that person can rejoin. Removing a member also removes any assigned role or admin mute, so a new invitation starts as an ordinary member.

Moderation travels over existing authenticated HTTPS/WSS signaling. Audio/video remain encrypted between peers; no media is sent to the DigitalOcean server. Incoming packets may still be visible in the connection inspector while playback is blocked on the receiver. Moderation is enforced by the official receiving clients, not by inspecting audio at a media server.

Older apps retain ordinary calls, ordinary group calls and unmuted recurring meetings. If an admin imposes a mute, older receivers that cannot enforce it are disconnected with an update message; they must update before rejoining a meeting with an active admin mute. Updated browsers advertise support automatically. Use Mac app 1.0.8+9 or later for admin controls.

## Raise hand to speak

**Raise hand to speak** is optional and off by default. Any current admin can turn it on or off in meeting details or in **People** during the call, on web or Mac. The setting is saved with the meeting link. Admins can speak freely; other participants, including guests, need approval before unmuting.

Participants choose **Raise hand** and see **Hand raised · Waiting for an admin**. Raised hands appear first in People, with a count on the call controls. An admin opens the participant's menu and chooses **Allow to speak**. Only the approved person hears a quiet chime and sees **You can unmute and speak now**. Their microphone stays off until they choose **Unmute** (or **Use mic** if they joined to listen).

**Lower hand** cancels a pending request. **Finish speaking** gives up an approved turn; an admin can also choose **End speaking turn**. Both immediately block outgoing and incoming microphone audio again. Leaving, reconnecting, or restarting the service clears requests and approvals. Disabling the feature clears the queue and restores ordinary unmute permission, preserving any separate admin mutes and keeping microphones off until their users choose otherwise.

Speaking permission is enforced with the authenticated moderation roster on every supported receiver, including when a sender ignores its own microphone controls. Only current admins can change the setting or approve a request. Approval applies to a joined participant who has raised their hand; it cannot start capture or unmute anyone. Clients that do not advertise raise-hand support must update before joining an enabled meeting and are removed if the feature is enabled during their call.

The server tests cover authorization, demotion, request/grant cleanup, persistence, and compatibility. The browser integration test in `tests/raise-hand.mjs` covers real peer audio enforcement, guest controls, private single-play chimes, explicit unmute, ending turns, rejoining, disabling the feature, and narrow mobile layouts. Flutter tests cover permission transitions, chime deduplication, and microphone consent.

## Persistence and validation

The additive `meeting_controls` table stores assigned admin roles and admin mutes, keyed to `meeting_members`. Removing membership cascades to its controls. The original roster schema is retained for older binary compatibility. Existing owners obtain admin status directly from the meeting's owner field, including links created before this release. The server rechecks the current role for every action and publishes live roster revisions after a change; a stale menu cannot retain privileges after demotion.

The test suite checks owner protection, privilege escalation attempts, immediate demotion, kicking and rejoin denial, mute persistence, restore/migration, updated receiver enforcement and old-client compatibility. Browser tests simulate a sender ignoring its mute and check that the receiver still disables its audio. Signed native/browser tests cover role appointment, actual native receiving-track state, native forced mute, privacy-preserving release, and kicking. See the [release manifest](meeting-admins-release.json) for results and deployment details. Synthetic tracks are used; physical microphone capture and WAN performance are not validated by these tests.

Native moderation also applies to tracks obtained directly from each peer connection's receivers; changing a stream wrapper's cached flag alone did not reliably disable the native audio receiver. The integration test checks fresh platform receiver state. Kick cleanup keeps the app busy until capture and peer teardown finish, preventing a new call from racing the previous capture session.

The Mac build includes a project-local WebRTC renderer fix: queued frame callbacks check their weak renderer reference before accessing its fields. This prevents a crash when a participant's renderer is disposed while a frame is queued. The CocoaPods build copies the patched source into this project's ignored Pods directory; the shared Flutter package cache and other apps are untouched.

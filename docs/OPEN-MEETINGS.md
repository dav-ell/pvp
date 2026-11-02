# Open invite links

In the browser, select **Create meeting link → Who can join? → Anyone with the link**. In the Mac app, open **People → Meetings** and enable **Anyone with the link** when creating the meeting. Enter a name, create the permanent link and copy it. Private, invited-friends-only meetings remain the default; existing links retain their access policy.

Anyone with an open link can preview it in the browser, enter a display name and select **Join meeting** without creating an account. They can also choose **Sign in instead**. Previewing does not enroll them, create a guest session or capture media. Joining starts microphone capture; the camera stays off until enabled. Signed-in users continue to join with their existing account and do not need to be friends with the owner.

Guests get a temporary identity scoped to that one meeting. They can use audio, video, screen sharing, chat and file transfers, but cannot create meetings, add friends, place direct calls or become admins. A guest is labeled **Guest** in the browser and updated Mac meeting controls. The Mac app still requires an account; accountless guests join through the browser.

Meetings support up to 16 members, counting the owner, saved account memberships and currently joined guests. Guest slots are released on leave or disconnect. Account members remain enrolled for later use. Guest identities are held only in server memory, using hashed random tokens and an HttpOnly, SameSite=Strict browser-session cookie (Secure on HTTPS). Their absolute lifetime is eight hours, without renewal. Refreshing can restore the guest identity but never starts capture automatically. Sign-out, expiry or a service restart ends the guest session; the permanent meeting link remains usable.

The owner remains admin and can appoint other admins. Admin mute, permission to unmute, and kicking work across browser and Mac participants. A kick removes membership and persistently blocks that account from using the link again. For guests, a kick blocks their current guest session and stops their media. Guests can obtain a new identity by clearing cookies or starting a new session, so guest kicks cannot identify or permanently ban a person. An owner can restore access by becoming accepted friends and adding that person again. Deleting the meeting revokes the entire link. Merely forwarding an open link can grant a new person access, so share it with the audience you want to admit.

Media remains encrypted between peers. Open admission does not authorize ordinary direct calls, grant admin privileges, or create friendships. Friendship removal does not revoke an open meeting membership; use its Kick action instead.

The additive `meeting_access` table stores the access policy and `meeting_blocks` stores kicked accounts. These are included in a complete SQLite backup. Old meetings without access rows remain private; original meeting and member schemas stay unchanged. Older apps can join open links through the updated service; Mac 1.0.9+10 adds the creation option. When pointed at an older service, the Mac open-link switch is disabled.

Validation includes non-friend browser media traffic with real DTLS/SRTP, private admission denial, preview without capture/enrollment, privilege denial, kick/rejoin denial, membership cap, backup/restore, and signed native/browser open-meeting media and moderation. Physical microphone capture and WAN reliability are not covered by these synthetic local integrations. See [the release manifest](open-meetings-release.json).

## Guest validation

`npm run test:guests` starts an isolated service and checks accountless mobile entry, explicit capture, real encrypted browser audio and chat, input escaping, account-session preservation, private/revoked-link denial, guest moderation and kicked-session denial. Rust tests also cover scoped signaling permissions, non-renewing expiry, the 16-member cap, released guest slots and retained moderator mutes. Guest joins create no database accounts, persistent session records or saved memberships. Set `PVP_TEST_URL` to verify another service and `PVP_TEST_ACCOUNT_FILE` to record the exact temporary owner account for cleanup.

## Guest release on October 17, 2026

Signaling/browser 0.3.19 is deployed at [lopixel.space](https://lopixel.space), and the signed universal [Mac 1.0.18 download](https://lopixel.space/downloads/PVP-macOS-1.0.18.zip) includes guest labels and moderation controls. The complete guest integration also passed against public HTTPS, including actual encrypted audio and chat, mobile entry, mute/kick, and denied rejoining. All 22 embedded public assets and the complete Mac archive match the tested builds. See [validation, hashes and rollback backups](guest-meetings-release.json). The earlier release manifest above describes account-only open admission.

## Browser entry on phones

As of production 0.3.20, shared links open a dedicated meeting invitation for members and guests. **Join to listen** requires no microphone permission; **Use mic** enables speaking during the existing call. Permission recovery stays visible, refreshed guests get **Rejoin to listen**, and meeting calls use the full phone width. Existing open/private access, capacity and moderation remain enforced. See [mobile meeting behavior](MOBILE-MEETINGS.md) and [release verification](mobile-meetings-release.json).

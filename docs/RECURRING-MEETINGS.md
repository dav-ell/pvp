# Permanent recurring meeting links

In either the browser or Mac app, select **Meetings**, enter a name, choose accepted friends, and select **Create permanent link**. Copy that HTTPS link into your weekly calendar event. Invitees also see the meeting under Meetings. Up to sixteen members can join; the owner does not need to be online or present.

Opening a link shows the meeting and its approved members. Capture starts only after **Join meeting**. The browser offers **Open in Mac app**, which opens the same meeting in PVP. Sign in first if necessary. The Mac app also accepts pasted HTTPS links. A link for another PVP service cannot switch the app's configured service or forward its credentials there.

Links have no expiry, idle timeout, or dependency on a running call. Everyone leaving ends only that call. Returning through the same link creates a fresh call. The owner can invite accepted friends, appoint admins, or explicitly delete the link. The owner and appointed admins can mute and kick other members; see [meeting admin controls](MEETING-ADMINS.md). Removed members are disconnected from its active call; deleting the link ends its call and prevents reuse. Removing a friendship with the owner revokes membership. Private links require an invitation; open links also admit accountless browser guests.

Calls use the existing encrypted P2P group engine. The server stores account, membership and meeting metadata and coordinates signaling; it does not receive or forward media. Browser video forwarding and native/browser interoperability retain the behavior described in [GROUP-CALLS.md](GROUP-CALLS.md).

## Durability and moving instances

Stable meeting IDs, names, owners and member lists live in the existing SQLite database `/var/lib/pvp/pvp.sqlite`, in `meetings` and `meeting_members`. Assigned roles and persistent admin mutes live in `meeting_controls`. Live call IDs and peer connections remain temporary. Service restarts preserve links and memberships. An additive schema migration preserves existing accounts, friendships and saved sessions. Older dedicated apps continue ordinary calls; recurring meetings require the updated app.

To move instances, **restore the complete database and keep the same HTTPS domain** (`lopixel.space`). Meeting IDs are independent of the VM's IP address. Copying only a database file while it is live can miss WAL writes; use SQLite's online backup API. Live calls will end during migration and members can rejoin through the same link.

Run from your Mac:

```sh
bash scripts/backup-meetings.sh
```

This creates an integrity-checked, mode-0600 consistent backup outside the VM at `~/Library/Application Support/PVP/Backups/`. It includes sensitive account/session data; protect it. Set `PVP_SSH_HOST`, `PVP_SSH_KEY`, or `PVP_BACKUP_DIR` to use another host/key/location. It does not register a recurring backup job; run it periodically and before migration. A backup only contains meetings created or changed before its snapshot.

Restore onto a provisioned replacement instance:

1. Stop `pvp-signaling`. Retain its current database separately for rollback.
2. Restore the backup as `/var/lib/pvp/pvp.sqlite`, owned by `pvp:pvp` and mode `0600`. Remove only the stopped database's obsolete `-wal`/`-shm` sidecars before restoring.
3. Retain `PVP_ORIGIN=https://lopixel.space`, run signaling version 0.3.6 or later, and start the service. Verify `/health` and SQLite integrity.
4. Point the existing domain to the replacement instance and configure HTTPS. Retain the old VM until restoration and client access have been checked.

A link cannot survive loss of every copy of its database or abandonment of its domain. Preserving those two things allows the same calendar links to outlive the original DigitalOcean instance.

## Deployment

Production is signaling/browser 0.3.9, and the installed Mac app is 1.0.10+11, including [meeting admin controls](MEETING-ADMINS.md). The previous app and production binary/database are retained for rollback. An integrity-checked off-VM backup is stored on the Mac under `~/Library/Application Support/PVP/Backups/`; its exact path is in the [latest release manifest](meeting-chat-release.json). This is a snapshot, not an automatically scheduled backup.

## Validation

The automated tests exercise browser-created links without capture, owner-offline joins, real encrypted browser audio/video, repeated joins after the last person leaves, server restart, restored-database migration, unauthorized access, member removal and deletion. Rust tests enforce sixteen-member limits and accepted friendship. Mac tests validate service-bound link parsing, minimum-window layouts, and native/browser recurring meeting interoperability. See [release manifest](recurring-meetings-release.json) for the actual deployment and test results.

## Open invite links

New meetings can use **Anyone with the link** instead of invited-friends-only admission. Visitors can join in the browser with a display name and no account, or sign in to retain membership. Kicks block account members or the current guest session. See [open-link behavior](OPEN-MEETINGS.md). Existing links stay private.

### Portable backup authentication behavior

New backups from `scripts/backup-meetings.sh` omit session records while preserving accounts, password hashes, friendships, meetings and history. Users sign in again after restoring one. This prevents restoring the snapshot from reviving an old revoked sign-in token. Older backup files retain their previous behavior. Backups are permission-restricted SQLite files, not encrypted archives; protect their storage accordingly.

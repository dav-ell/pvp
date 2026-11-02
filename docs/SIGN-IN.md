# Staying signed in

PVP 1.0.6 and signaling 0.3.5 keep users signed in automatically across browser visits and Mac app restarts.

Browsers store the session in a persistent HttpOnly, SameSite=Strict cookie, marked Secure in production. Opening PVP restores the account and refreshes the cookie. An open signed-in page refreshes it hourly. Passwords and session tokens are not stored in browser localStorage.

The Mac app stores the session in macOS Keychain, scoped to the selected service, and restores it on launch. Quitting or closing the window does not sign out. Renderer or device setup failures cannot prevent restoration. A temporary service or Keychain access failure retains the saved sign-in and retries; a confirmed expired/revoked session is cleared.

Valid server sessions renew with authenticated activity, including the connected Mac app's background heartbeat. Renewal writes are limited to approximately once per hour. Sessions expire after approximately thirty days without authenticated activity. Existing valid sessions are preserved by this update; no account/database migration or mandatory sign-in is required.

Signing out revokes that session on the server and removes the saved cookie/Keychain item. A copied revoked token cannot restore an account. Browser renewals are canceled before sign-out or account changes; ordinary bootstrap responses do not issue cookies, preventing a delayed initial response from overwriting a newer login.

Validation includes a persistent browser profile closed and reopened, startup outage recovery, hourly cookie renewal, logout/revocation, native restoration despite renderer failure, and expired/unavailable-session behavior. A signed Mac integration runs two separate app processes: the first saves a real Keychain session; the second restores the account without credentials and verifies that sign-out deletes the item. Test accounts use isolated local services and do not touch the production account's Keychain entry.

See [release manifest](sign-in-release.json) for installed and production versions, checksums, validation, and rollback locations. Group calls and the preceding one-to-one behavior remain available.

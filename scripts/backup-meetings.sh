#!/usr/bin/env bash
# SQLite online backup to a different machine; never copy an active WAL DB alone.
set -euo pipefail
umask 077
server="${PVP_SSH_HOST:-root@143.198.19.179}"
key="${PVP_SSH_KEY:-$HOME/.ssh/id_ed25519}"
backup_dir="${PVP_BACKUP_DIR:-$HOME/Library/Application Support/PVP/Backups}"
mkdir -p "$backup_dir"
chmod 0700 "$backup_dir"
remote=$(ssh -o BatchMode=yes -i "$key" "$server" 'mktemp -d /tmp/pvp-portable-backup.XXXXXXXX')
[[ "$remote" =~ ^/tmp/pvp-portable-backup\.[[:alnum:]]+$ ]] || { printf 'Unexpected backup path\n' >&2; exit 1; }
cleanup() { ssh -o BatchMode=yes -i "$key" "$server" "rm -rf -- '$remote'" || true; }
trap cleanup EXIT
ssh -o BatchMode=yes -i "$key" "$server" "python3 - '$remote'" <<'PY'
import sys,sqlite3,os
path=sys.argv[1]+'/pvp.sqlite'
with sqlite3.connect('/var/lib/pvp/pvp.sqlite') as source, sqlite3.connect(path) as dest:
    source.backup(dest)
    # Restores must require fresh authentication instead of reviving revoked tokens.
    dest.execute('PRAGMA secure_delete=ON')
    dest.execute('DELETE FROM sessions')
    dest.commit()
    assert dest.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
os.chmod(path,0o600)
PY
filename="$backup_dir/pvp-$(date -u +%Y%m%dT%H%M%SZ)-$$.sqlite"
staging="$filename.partial"
scp -q -o BatchMode=yes -i "$key" "$server:$remote/pvp.sqlite" "$staging"
python3 - "$staging" <<'PY'
import sys,sqlite3
with sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True) as db:
    assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
PY
chmod 0600 "$staging"
mv "$staging" "$filename"
printf 'Portable database backup: %s\n' "$filename"

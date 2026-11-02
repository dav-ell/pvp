//! Private database files independent of the launcher's umask.
use rusqlite::{Connection, OpenFlags};

pub(super) fn open(path: &str) -> rusqlite::Result<Connection> {
    if path == ":memory:" {
        return Connection::open_in_memory();
    }
    #[cfg(unix)]
    let path = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        use std::{
            fs, io,
            path::{Path, PathBuf},
        };
        let protect = || -> io::Result<PathBuf> {
            let requested = Path::new(path);
            let parent = fs::canonicalize(
                requested
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?;
            // Resolve system aliases (such as macOS /var) once, and use this
            // checked directory for both precreation and SQLite's own open.
            let uid = unsafe { libc::geteuid() };
            for ancestor in parent.ancestors() {
                let directory = fs::metadata(ancestor)?;
                if !directory.is_dir()
                    || (directory.uid() != 0 && directory.uid() != uid)
                    || (directory.mode() & 0o022 != 0 && directory.mode() & 0o1000 == 0)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Database directories must not allow replacement by other users",
                    ));
                }
            }
            let path = parent.join(requested.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "A database filename is required",
                )
            })?);
            for (name, create) in [
                (path.clone(), true),
                (suffix(&path, "-wal"), false),
                (suffix(&path, "-shm"), false),
                (suffix(&path, "-journal"), false),
            ] {
                let file = match fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(create)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&name)
                {
                    Ok(file) => file,
                    Err(error) if !create && error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                let metadata = file.metadata()?;
                if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != uid {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Database files must be regular, singly linked files owned by the service",
                    ));
                }
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            Ok(path)
        };
        protect().map_err(|error| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
                Some(error.to_string()),
            )
        })?
    };
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
}

#[cfg(unix)]
fn suffix(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn directory() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pvp-db-security-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn database_and_live_wal_files_are_private_and_old_modes_are_repaired() {
        let dir = directory();
        let path = dir.join("state.sqlite");
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let db = open(path.to_str().unwrap()).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE secret(value TEXT); INSERT INTO secret VALUES('fixture');").unwrap();
        for name in ["state.sqlite", "state.sqlite-wal", "state.sqlite-shm"] {
            assert_eq!(
                std::fs::metadata(dir.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::set_permissions(
            dir.join("state.sqlite-wal"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let second = open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("state.sqlite-wal"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(second);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn symlinked_database_sidecars_hardlinks_and_replaceable_directories_are_rejected() {
        let dir = directory();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"do not change").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = dir.join("state.sqlite");
        symlink(&victim, &path).unwrap();
        assert!(open(path.to_str().unwrap()).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&victim, &path).unwrap();
        assert!(open(path.to_str().unwrap()).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(&victim, dir.join("state.sqlite-wal")).unwrap();
        assert!(open(path.to_str().unwrap()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not change");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::remove_file(dir.join("state.sqlite-wal")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open(path.to_str().unwrap()).is_err());
        let child = dir.join("private");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open(child.join("state.sqlite").to_str().unwrap()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

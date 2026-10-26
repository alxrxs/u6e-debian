//! What the runner keeps across its restarts, in its state directory (the
//! service's `StateDirectory`, its own alone): the latest configuration it
//! signed for each AP, which holds the site's secrets (so every file is
//! 0600), the image it staged on each AP, the rollout under way, and the
//! results the controller has not acknowledged yet. Each file is its format
//! ([`FORMAT`]) and one frame (`u6e_proto::frame`), written beside the old one
//! and renamed over it, so a crash leaves either; the bytes of each frame are
//! wiped once used. A file of another format, or that does not decode, is
//! not read: the runner sets it aside as `<name>.corrupt-<ms>` and goes on
//! without it, and says so until someone removes it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde::de::DeserializeOwned;
use u6e_proto::frame::{read_frame, write_frame, zeroize};

/// What every file starts with: a mark, and the format of what follows,
/// raised with every change to what the files hold.
const MARK: &[u8; 4] = b"U6DS";
pub const FORMAT: u16 = 2;
/// What a file set aside is named after: `<name>.corrupt-<ms>`.
const ASIDE: &str = ".corrupt-";

/// The state directory.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// The store in `dir`, made (0700) if it is not there.
    pub fn open(dir: &Path) -> io::Result<Store> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?;
        Ok(Store { dir: dir.into() })
    }

    /// What `name` holds; `None` when it holds nothing. A file that is not of
    /// this [`FORMAT`] or does not decode is [`Unreadable`].
    pub fn load<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, Unreadable> {
        let path = self.dir.join(name);
        let mut bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                let e = io::Error::new(e.kind(), format!("{}: {e}", path.display()));
                return Err(Unreadable::Io(e));
            }
        };
        let v = match bytes.split_first_chunk::<6>() {
            Some((head, body)) if &head[..4] == MARK => {
                match u16::from_le_bytes([head[4], head[5]]) {
                    FORMAT => read_frame(&mut &body[..]).map_err(|e| e.to_string()),
                    other => Err(format!("of format {other}, not {FORMAT}")),
                }
            }
            _ => Err(format!("not of format {FORMAT}")),
        };
        zeroize(&mut bytes);
        v.map(Some).map_err(Unreadable::Corrupt)
    }

    /// Moves `name` aside, as `<name>.corrupt-<ms>`; that name.
    pub fn set_aside(&self, name: &str) -> io::Result<String> {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let aside = format!("{name}{ASIDE}{ms}");
        fs::rename(self.dir.join(name), self.dir.join(&aside))?;
        File::open(&self.dir)?.sync_all()?;
        Ok(aside)
    }

    /// The files set aside, and when, oldest first.
    pub fn set_aside_files(&self) -> io::Result<Vec<(String, u64)>> {
        let mut files: Vec<(String, u64)> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter_map(|n| {
                let (_, ms) = n.rsplit_once(ASIDE)?;
                let ms = ms.parse().ok()?;
                Some((n, ms))
            })
            .collect();
        files.sort_by_key(|(n, ms)| (*ms, n.clone()));
        Ok(files)
    }

    /// Makes `name` hold `v`.
    pub fn save<T: Serialize>(&self, name: &str, v: &T) -> io::Result<()> {
        let path = self.dir.join(name);
        let temp = self.dir.join(format!(".{name}.new"));
        let mut bytes = MARK.to_vec();
        bytes.extend_from_slice(&FORMAT.to_le_bytes());
        let written = write_frame(&mut bytes, v).and_then(|()| {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp)?;
            f.write_all(&bytes)?;
            f.sync_all()
        });
        zeroize(&mut bytes);
        written?;
        fs::rename(&temp, &path)?;
        File::open(&self.dir)?.sync_all()
    }

    /// Empties `name`.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        match fs::remove_file(self.dir.join(name)) {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
            _ => File::open(&self.dir)?.sync_all(),
        }
    }
}

/// Why a file was not read.
#[derive(Debug)]
pub enum Unreadable {
    /// It could not be read at all: the runner cannot go on.
    Io(io::Error),
    /// It is of another format, or does not decode: why.
    Corrupt(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use crate::tests::TestDir;

    #[test]
    fn saved_loaded_and_removed_owner_only() {
        let t = TestDir::new();
        let s = Store::open(&t.path().join("state")).unwrap();
        assert_eq!(s.load::<Vec<String>>("x").unwrap(), None);
        s.save("x", &vec!["secret".to_owned()]).unwrap();
        assert_eq!(
            s.load::<Vec<String>>("x").unwrap(),
            Some(vec!["secret".to_owned()])
        );
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(t.path().join("state")), 0o700);
        assert_eq!(mode(t.path().join("state/x")), 0o600);
        s.remove("x").unwrap();
        s.remove("x").unwrap();
        assert_eq!(s.load::<Vec<String>>("x").unwrap(), None);
    }

    /// A file of another format, or that does not decode, is not read, and
    /// can be set aside, which the store then lists.
    #[test]
    fn another_format_is_not_read() {
        let t = TestDir::new();
        let s = Store::open(&t.path().join("state")).unwrap();
        s.save("x", &vec!["kept".to_owned()]).unwrap();
        let path = t.path().join("state/x");
        let mut bytes = fs::read(&path).unwrap();
        bytes[4] = 9;
        fs::write(&path, &bytes).unwrap();
        let why = |s: &Store| match s.load::<Vec<String>>("x") {
            Err(Unreadable::Corrupt(why)) => why,
            other => panic!("{other:?}"),
        };
        assert_eq!(why(&s), "of format 9, not 2");
        fs::write(&path, b"garbage").unwrap();
        assert_eq!(why(&s), "not of format 2");
        // An older file of the same format whose frame no longer decodes.
        s.save("x", &7u8).unwrap();
        assert!(matches!(
            s.load::<Vec<String>>("x"),
            Err(Unreadable::Corrupt(_))
        ));
        let aside = s.set_aside("x").unwrap();
        assert!(aside.starts_with("x.corrupt-"));
        assert_eq!(s.load::<Vec<String>>("x").unwrap(), None);
        let listed = s.set_aside_files().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, aside);
    }
}

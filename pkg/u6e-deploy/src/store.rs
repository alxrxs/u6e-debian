//! What the runner keeps across its restarts, in its state directory (the
//! service's `StateDirectory`, its own alone): the latest configuration it
//! signed for each AP, which holds the site's secrets (so every file is
//! 0600), the image it staged on each AP, the rollout under way, and the
//! results the controller has not acknowledged yet. Each file is one frame
//! (`u6e_proto::frame`), written beside the old one and renamed over it, so a
//! crash leaves either; the bytes of each frame are wiped once used.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use u6e_proto::frame::{read_frame, write_frame, zeroize};

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

    /// What `name` holds; `None` when it holds nothing.
    pub fn load<T: DeserializeOwned>(&self, name: &str) -> io::Result<Option<T>> {
        let path = self.dir.join(name);
        let mut bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        };
        let v = read_frame(&mut bytes.as_slice());
        zeroize(&mut bytes);
        v.map(Some)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))
    }

    /// Makes `name` hold `v`.
    pub fn save<T: Serialize>(&self, name: &str, v: &T) -> io::Result<()> {
        let path = self.dir.join(name);
        let temp = self.dir.join(format!(".{name}.new"));
        let mut bytes = Vec::new();
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
}

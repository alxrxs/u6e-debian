//! The kept images, `<images>/<id>/` (`[rollouts] images`, the controller's
//! own, 0700): each an image as u6e-debian's build keeps it, its `MANIFEST`
//! (the AP it was built for on its `ap:` line, and a `<sha256>  <path>` line
//! for each file) and the four files a staging boots (`shim.bin`, `u6e.dtb`,
//! `u6e.initrd`, `Image`). Its id is the name its build gave it, which starts
//! with its build time and which the image reports as it runs
//! (`Hello::image`), so an AP's newest image is the greatest id.
//!
//! An image is added whole or not at all: its files are written into a
//! dot-named directory beside the others, each checked against its SHA-256
//! as it comes, and the directory renamed to its id once every one is
//! there. One is checked against its `MANIFEST` again before every staging.
//! A prune keeps what it is told to and the newest of each AP, and renames
//! an image to a dot-name before it removes it, so a prune cut short leaves
//! nothing under an image's name; dot-names are never images, and what one
//! leaves is removed when the store opens.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use aws_lc_rs::digest;
use u6e_proto::mac;

/// The files a staging boots, in the order it stages them.
pub const PAYLOADS: [&str; 4] = ["shim.bin", "u6e.dtb", "u6e.initrd", "Image"];
/// The largest `MANIFEST` read.
pub const MANIFEST_MAX: usize = 64 * 1024;
/// The most an image's files may hold together: a real one is under 100 MB.
pub const IMAGE_MAX: u64 = 256 * 1024 * 1024;

/// Whether `id` could name a kept image: one path component of letters,
/// digits, `.`, `_` and `-`, not starting with a dot.
pub fn image_name(id: &str) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    (1..=128).contains(&id.len()) && !id.starts_with('.') && id.chars().all(ok)
}

/// The AP a `MANIFEST` names: the first word of its `ap:` line.
pub fn ap_of(manifest: &str) -> Option<&str> {
    let line = manifest.lines().find_map(|l| l.strip_prefix("ap:"))?;
    line.split_whitespace().next()
}

/// The files a `MANIFEST` lists, by name (the last part of each path), with
/// their SHA-256; exactly [`PAYLOADS`], each once.
pub fn listed(manifest: &str) -> Result<Vec<(String, [u8; 32])>, String> {
    let mut files: Vec<(String, [u8; 32])> = Vec::new();
    for line in manifest.lines() {
        let Some((hex, path)) = line.split_once("  ") else {
            continue;
        };
        let lower = !hex.bytes().any(|b| b.is_ascii_uppercase());
        let Some(sha256) = mac::unhex(hex).filter(|_| lower) else {
            continue;
        };
        let name = path.rsplit('/').next().unwrap_or_default();
        if !PAYLOADS.contains(&name) || files.iter().any(|(n, _)| n == name) {
            return Err(format!(
                "the MANIFEST lists {path:.128}, not a file to boot"
            ));
        }
        files.push((name.to_owned(), sha256));
    }
    if files.len() != PAYLOADS.len() {
        return Err(format!(
            "the MANIFEST does not list all of {}",
            PAYLOADS.join(", ")
        ));
    }
    Ok(files)
}

/// A kept image of an AP: its directory, and what its `MANIFEST` lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub id: String,
    pub dir: PathBuf,
    pub files: Vec<(String, [u8; 32])>,
}

impl Kept {
    /// The path of payload `name`.
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

/// The store.
#[derive(Debug, Clone)]
pub struct Images {
    dir: PathBuf,
}

/// The SHA-256 of what `r` holds, at most `max` bytes; `None` past it.
fn sha256_of(mut r: impl Read, max: u64) -> io::Result<Option<[u8; 32]>> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut buf = vec![0; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max {
            return Ok(None);
        }
        ctx.update(&buf[..n]);
    }
    let mut h = [0; 32];
    h.copy_from_slice(ctx.finish().as_ref());
    Ok(Some(h))
}

/// A regular file at `p`, opened without following a link.
fn open_file(p: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

impl Images {
    /// The store in `dir`, made (0700) if it is not there; what a cut-short
    /// add or prune left is removed.
    pub fn open(dir: &Path) -> io::Result<Images> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(Images { dir: dir.into() })
    }

    fn manifest(&self, id: &str) -> Option<String> {
        let mut text = String::new();
        let f = open_file(&self.dir.join(id).join("MANIFEST")).ok()?;
        f.take(MANIFEST_MAX as u64).read_to_string(&mut text).ok()?;
        Some(text)
    }

    /// Every kept image by the AP it is for, oldest first.
    pub fn index(&self) -> io::Result<BTreeMap<String, Vec<String>>> {
        let mut index: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entry in fs::read_dir(&self.dir)? {
            let Ok(id) = entry?.file_name().into_string() else {
                continue;
            };
            if !image_name(&id) {
                continue;
            }
            if let Some(ap) = self.manifest(&id).as_deref().and_then(ap_of) {
                index.entry(ap.to_owned()).or_default().push(id);
            }
        }
        for ids in index.values_mut() {
            ids.sort();
        }
        Ok(index)
    }

    /// The kept image `id` of `ap`, checked against its `MANIFEST`: every
    /// file there, a regular file, and the one it lists.
    pub fn verified(&self, ap: &str, id: &str) -> Result<Kept, String> {
        if !image_name(id) {
            return Err(format!("{id:.128} is not an image's name"));
        }
        let manifest = self
            .manifest(id)
            .ok_or_else(|| format!("no image {id} is kept"))?;
        match ap_of(&manifest) {
            Some(of) if of == ap => {}
            Some(of) => return Err(format!("{id} is {of:.64}'s image, not {ap}'s")),
            None => return Err(format!("{id}'s MANIFEST names no AP")),
        }
        let kept = Kept {
            id: id.to_owned(),
            dir: self.dir.join(id),
            files: listed(&manifest).map_err(|e| format!("{id}: {e}"))?,
        };
        for (name, want) in &kept.files {
            let sha = open_file(&kept.file(name))
                .and_then(|f| sha256_of(f, IMAGE_MAX))
                .map_err(|e| format!("{id}/{name}: {e}"))?;
            if sha.as_ref() != Some(want) {
                return Err(format!("{id}/{name} is not the file its MANIFEST lists"));
            }
        }
        Ok(kept)
    }

    /// Starts adding image `id` of `manifest`, which must name one of `aps`:
    /// `None` when it is kept already, with that `MANIFEST`.
    pub fn add(&self, id: &str, manifest: &str, aps: &[&str]) -> Result<Option<Adding>, String> {
        if !image_name(id) {
            return Err(format!("{id:.128} is not an image's name"));
        }
        if manifest.len() > MANIFEST_MAX {
            return Err("the MANIFEST is too long to be one".into());
        }
        let ap = ap_of(manifest).ok_or("the MANIFEST names no AP")?;
        if !aps.contains(&ap) {
            return Err(format!(
                "the MANIFEST names {ap:.64}, which is no configured AP"
            ));
        }
        let files = listed(manifest)?;
        if let Some(kept) = self.manifest(id) {
            return if kept == manifest {
                Ok(None)
            } else {
                Err(format!("another image {id} is kept"))
            };
        }
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .dir
            .join(format!(".adding-{id}-{}-{n}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&temp)
            .map_err(|e| format!("{}: {e}", temp.display()))?;
        fs::write(temp.join("MANIFEST"), manifest).map_err(|e| e.to_string())?;
        Ok(Some(Adding {
            id: id.to_owned(),
            ap: ap.to_owned(),
            temp,
            files,
            next: 0,
            current: None,
            total: 0,
            target: self.dir.join(id),
        }))
    }

    /// Removes every image but those of `keep` and the newest `newest` of
    /// each AP; the ids removed.
    pub fn prune(&self, keep: &BTreeSet<String>, newest: usize) -> io::Result<Vec<String>> {
        let mut removed = Vec::new();
        for ids in self.index()?.into_values() {
            let old = ids.len().saturating_sub(newest);
            for id in ids.into_iter().take(old).filter(|id| !keep.contains(id)) {
                let aside = self.dir.join(format!(".{id}.pruning"));
                fs::rename(self.dir.join(&id), &aside)?;
                fs::remove_dir_all(&aside)?;
                removed.push(id);
            }
        }
        Ok(removed)
    }
}

/// An image being added: its files come one at a time, in its `MANIFEST`'s
/// order, each ended by an empty chunk. Dropped before it is done, it leaves
/// nothing.
pub struct Adding {
    pub id: String,
    pub ap: String,
    temp: PathBuf,
    files: Vec<(String, [u8; 32])>,
    next: usize,
    current: Option<(File, digest::Context)>,
    total: u64,
    target: PathBuf,
}

impl Drop for Adding {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp);
    }
}

impl Adding {
    /// The files, in the order they are to come.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|(n, _)| n.as_str())
    }

    /// Takes the next part of the file being sent; an empty one ends it.
    /// True once the last file ended.
    pub fn chunk(&mut self, bytes: &[u8]) -> Result<bool, String> {
        let Some((name, want)) = self.files.get(self.next).cloned() else {
            return Err("more than the MANIFEST lists".into());
        };
        if bytes.is_empty() {
            let (f, ctx) = match self.current.take() {
                Some(c) => c,
                None => (self.create(&name)?, digest::Context::new(&digest::SHA256)),
            };
            f.sync_all().map_err(|e| format!("{name}: {e}"))?;
            if ctx.finish().as_ref() != want {
                return Err(format!("{name} is not the file the MANIFEST lists"));
            }
            self.next += 1;
            return Ok(self.next == self.files.len());
        }
        self.total += bytes.len() as u64;
        if self.total > IMAGE_MAX {
            return Err(format!("its files hold more than {IMAGE_MAX} B"));
        }
        if self.current.is_none() {
            let f = self.create(&name)?;
            self.current = Some((f, digest::Context::new(&digest::SHA256)));
        }
        let Some((f, ctx)) = self.current.as_mut() else {
            return Err("no file".into());
        };
        ctx.update(bytes);
        f.write_all(bytes).map_err(|e| format!("{name}: {e}"))?;
        Ok(false)
    }

    fn create(&self, name: &str) -> Result<File, String> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.temp.join(name))
            .map_err(|e| format!("{name}: {e}"))
    }

    /// Keeps the image under its id, once every file came.
    pub fn finish(self) -> Result<(), String> {
        if self.next != self.files.len() {
            return Err("not every file the MANIFEST lists came".into());
        }
        fs::rename(&self.temp, &self.target).map_err(|e| e.to_string())?;
        let dir = self.target.parent().unwrap_or(Path::new("/"));
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::testdir::TestDir;

    /// A MANIFEST of `ap` listing `files`, as the build writes one.
    pub fn manifest(ap: &str, files: &[(&str, &[u8])]) -> String {
        let mut m = format!("ap:        {ap} (u6e-{ap}, 192.0.2.16/24)\nkernel:    x\n");
        for (name, body) in files {
            let sha = digest::digest(&digest::SHA256, body);
            m += &format!("{}  out/{name}\n", mac::hex(sha.as_ref()));
        }
        m
    }

    /// The four payloads of an image, each its name and `tag`.
    pub fn payloads(tag: &str) -> Vec<(&'static str, Vec<u8>)> {
        PAYLOADS
            .iter()
            .map(|n| (*n, format!("{n} of {tag}").into_bytes()))
            .collect()
    }

    /// Adds image `id` of `ap` to `images` as a local caller sends it.
    pub fn add(images: &Images, id: &str, ap: &str) -> Result<(), String> {
        let files = payloads(id);
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, b)| (*n, b.as_slice())).collect();
        let Some(mut a) = images.add(id, &manifest(ap, &refs), &["ap1", "ap2"])? else {
            return Ok(());
        };
        for (_, body) in &files {
            a.chunk(body)?;
            a.chunk(&[])?;
        }
        a.finish()
    }

    #[test]
    fn an_image_is_added_whole_and_verified() {
        let t = TestDir::new();
        let images = Images::open(&t.path().join("images")).unwrap();
        add(&images, "20261101-1-ap1", "ap1").unwrap();
        let kept = images.verified("ap1", "20261101-1-ap1").unwrap();
        assert_eq!(kept.files.len(), 4);
        assert_eq!(
            fs::read(kept.file("u6e.dtb")).unwrap(),
            b"u6e.dtb of 20261101-1-ap1"
        );
        assert_eq!(
            images.verified("ap2", "20261101-1-ap1"),
            Err("20261101-1-ap1 is ap1's image, not ap2's".into())
        );
        assert_eq!(
            images.verified("ap1", "../x"),
            Err("../x is not an image's name".into())
        );
        // Again with the same MANIFEST: kept already. With another: refused.
        add(&images, "20261101-1-ap1", "ap1").unwrap();
        let other = manifest("ap1", &[("Image", b"x")]);
        assert!(images.add("20261101-1-ap1", &other, &["ap1"]).is_err());
        // A file altered once kept fails the check before a staging.
        fs::write(kept.file("Image"), b"another kernel").unwrap();
        assert_eq!(
            images.verified("ap1", "20261101-1-ap1"),
            Err("20261101-1-ap1/Image is not the file its MANIFEST lists".into())
        );
        assert_eq!(images.index().unwrap()["ap1"], ["20261101-1-ap1"]);
    }

    /// A file that is not what the MANIFEST lists, or an image for no AP of
    /// the configuration, is never kept, and leaves nothing behind.
    #[test]
    fn what_is_not_its_manifest_is_never_kept() {
        let t = TestDir::new();
        let dir = t.path().join("images");
        let images = Images::open(&dir).unwrap();
        let files = payloads("a");
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, b)| (*n, b.as_slice())).collect();
        let m = manifest("ap1", &refs);
        assert_eq!(
            images.add("a-ap9", &manifest("ap9", &refs), &["ap1"]).err(),
            Some("the MANIFEST names ap9, which is no configured AP".into())
        );
        assert!(
            images
                .add("a-ap1", &manifest("ap1", &refs[..3]), &["ap1"])
                .is_err()
        );
        let mut a = images.add("a-ap1", &m, &["ap1"]).unwrap().unwrap();
        a.chunk(b"not the shim").unwrap();
        assert_eq!(
            a.chunk(&[]),
            Err("shim.bin is not the file the MANIFEST lists".into())
        );
        drop(a);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        // Cut short: nothing under its name, and nothing left once reopened.
        let mut a = images.add("a-ap1", &m, &["ap1"]).unwrap().unwrap();
        a.chunk(&files[0].1).unwrap();
        a.chunk(&[]).unwrap();
        assert_eq!(
            a.finish(),
            Err("not every file the MANIFEST lists came".into())
        );
        std::mem::forget(images.add("a-ap1", &m, &["ap1"]).unwrap());
        assert!(images.index().unwrap().is_empty());
        Images::open(&dir).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// A prune keeps what it is told to and the newest of each AP.
    #[test]
    fn a_prune_keeps_the_newest_and_what_it_is_told() {
        let t = TestDir::new();
        let images = Images::open(&t.path().join("images")).unwrap();
        for id in ["1-ap1", "2-ap1", "3-ap1", "4-ap1", "5-ap1", "1-ap2"] {
            let ap = &id[2..];
            add(&images, id, ap).unwrap();
        }
        let keep = BTreeSet::from(["1-ap1".to_owned()]);
        assert_eq!(images.prune(&keep, 3).unwrap(), ["2-ap1"]);
        let index = images.index().unwrap();
        assert_eq!(index["ap1"], ["1-ap1", "3-ap1", "4-ap1", "5-ap1"]);
        assert_eq!(index["ap2"], ["1-ap2"]);
    }
}

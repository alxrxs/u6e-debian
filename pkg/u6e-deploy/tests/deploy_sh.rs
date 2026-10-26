//! deploy.sh's side of the deploy runner, run as the repository has it in
//! a throwaway checkout: the boot of an access point (`ap-image.sh`'s
//! `boot_ap`) tells the runner what it staged (site.conf's `runner_staged`)
//! before it takes the boot as done; the kept images are pruned
//! (`prune_images`, `prune-images.py`) without ever losing one an access
//! point runs, goes back to, or was built for the current inputs; and
//! nothing is built with too little room.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A directory of the test's own, removed when it ends.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A checkout named `name` with what deploy.sh's functions need: the
/// repository's ap-image.sh, prune-images.py and deploy.sh, a staging that
/// logs what it boots, and an AP whose radios are always up.
fn checkout(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("u6e-deploy-sh-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    for d in ["boot", "stamps", "images"] {
        fs::create_dir_all(dir.join(d)).unwrap();
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for f in ["ap-image.sh", "prune-images.py", "deploy.sh"] {
        fs::copy(repo.join(f), dir.join(f)).unwrap();
    }
    fs::write(
        dir.join("boot/stage.sh"),
        "#!/bin/sh\necho \"staged ${1##*/}\" >> \"$(dirname \"$0\")/../events\"\n",
    )
    .unwrap();
    fs::write(dir.join("boot/lib.sh"), "ap_root() { echo 3; }\n").unwrap();
    fs::set_permissions(dir.join("boot/stage.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    TempDir(dir)
}

/// A kept image of `ap` named `id`, as prep-rootfs.sh keeps one.
fn keep(dir: &Path, id: &str, ap: &str) {
    let image = dir.join("images").join(id);
    fs::create_dir_all(&image).unwrap();
    fs::write(
        image.join("MANIFEST"),
        format!("ap:        {ap} (u6e-{ap})\n"),
    )
    .unwrap();
    fs::write(image.join("Image"), "kernel").unwrap();
}

/// Runs `script` after ap-image.sh in `dir`, as deploy.sh sources it.
fn run(dir: &Path, script: &str) -> Output {
    let script = format!("fail() {{ echo \"$*\" >&2; exit 1; }}; L=log; . ./ap-image.sh\n{script}");
    Command::new("bash")
        .args(["-c", &script])
        .current_dir(dir)
        .output()
        .unwrap()
}

/// What it printed, out and err.
fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn events(dir: &Path) -> Vec<String> {
    let text = fs::read_to_string(dir.join("events")).unwrap_or_default();
    text.lines().map(str::to_owned).collect()
}

/// The images left in `dir`.
fn left(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir.join("images"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_boot_the_runner_was_not_told_of_is_not_taken_as_done() {
    let t = checkout("boot");
    let dir = &t.0;
    keep(dir, "img-7-ap1", "ap1");
    let built = format!("key1 {}\n", dir.join("images/img-7-ap1").display());
    fs::write(dir.join("stamps/built-ap1"), built).unwrap();
    let boot = "runner_staged() { echo \"told $1 $2\" >> events; [ -e tell-ok ]; }
        boot_ap ap1 key1";
    // The runner is down: the AP was booted, the run fails, and no stamp
    // says the boot is done (but what the AP runs is recorded).
    assert!(!run(dir, boot).status.success());
    assert_eq!(events(dir), ["staged img-7-ap1", "told ap1 img-7-ap1"]);
    assert!(!dir.join("stamps/ap-ap1").exists());
    assert_eq!(
        fs::read_to_string(dir.join("stamps/running-ap1")).unwrap(),
        "img-7-ap1\n"
    );
    // The next run stages it again and tells the runner, which takes it.
    fs::write(dir.join("tell-ok"), "").unwrap();
    assert!(run(dir, boot).status.success());
    assert_eq!(events(dir)[2..], ["staged img-7-ap1", "told ap1 img-7-ap1"]);
    assert_eq!(
        fs::read_to_string(dir.join("stamps/ap-ap1")).unwrap(),
        "key1\n"
    );
    // Done: a run after it stages nothing and tells nothing.
    assert!(run(dir, boot).status.success());
    assert_eq!(events(dir).len(), 4);
}

/// The retention rule on a fixture tree: of each AP's images only the
/// newest three are kept by age, but never is one pruned that an AP runs,
/// that the runner goes back to (here an old one), or that was built for
/// the current inputs; nor anything that is not an image, nor an image
/// that holds more than files, nor a link to a directory elsewhere.
#[test]
fn pruning_keeps_what_any_ap_runs_goes_back_to_or_was_built_for() {
    let t = checkout("prune");
    let dir = &t.0;
    for n in 1..=8 {
        keep(dir, &format!("2026100{n}-x-ap1"), "ap1");
        keep(dir, &format!("2026100{n}-x-ap2"), "ap2");
    }
    // ap1 runs an old image, the runner goes back to an older one; ap2's
    // build of the current inputs is not booted yet, and it runs another.
    fs::write(dir.join("stamps/running-ap1"), "20261002-x-ap1\n").unwrap();
    fs::write(dir.join("stamps/built-ap1"), "k1 images/20261008-x-ap1\n").unwrap();
    fs::write(dir.join("stamps/ap-ap1"), "k1\n").unwrap();
    fs::write(dir.join("stamps/running-ap2"), "20261003-x-ap2\n").unwrap();
    fs::write(dir.join("stamps/built-ap2"), "k2 images/20261004-x-ap2\n").unwrap();
    fs::write(dir.join("stamps/ap-ap2"), "k0\n").unwrap();
    // Not images: a directory without a MANIFEST, a link to one elsewhere,
    // and an image holding a directory.
    fs::create_dir_all(dir.join("images/notes")).unwrap();
    let outside = dir.join("outside");
    keep(dir, "outside-image", "ap1");
    fs::rename(dir.join("images/outside-image"), &outside).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("images/20261000-link-ap1")).unwrap();
    keep(dir, "20261000-deep-ap2", "ap2");
    fs::create_dir_all(dir.join("images/20261000-deep-ap2/sub")).unwrap();
    let prune = "U6E_APS='ap1 ap2'
        runner_images() { printf '%s\\n' 20261001-x-ap1 20261005-x-ap2; }
        prune_images";

    // A dry run, by the script alone, lists and removes nothing; it reads
    // the stamps itself (ap1's running image is kept), not the runner.
    let out = Command::new("python3")
        .args([
            "-I",
            "prune-images.py",
            ".",
            "--ap",
            "ap1",
            "--ap",
            "ap2",
            "--dry-run",
        ])
        .current_dir(dir)
        .output()
        .unwrap();
    let listed = said(&out);
    assert!(
        listed.contains("would prune 20261001-x-ap1 (ap1)"),
        "{listed}"
    );
    assert!(!listed.contains("20261002-x-ap1"), "{listed}");
    assert_eq!(left(dir).len(), 19);

    let out = run(dir, prune);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        left(dir),
        [
            // An image holding a directory: out of the kept images' names,
            // left. ap1: the runner's way back, what it runs, the newest
            // three (its current build among them).
            ".20261000-deep-ap2.pruning",
            "20261000-link-ap1",
            "20261001-x-ap1",
            "20261002-x-ap1",
            "20261003-x-ap2",
            "20261004-x-ap2",
            "20261005-x-ap2",
            "20261006-x-ap1",
            "20261006-x-ap2",
            "20261007-x-ap1",
            "20261007-x-ap2",
            "20261008-x-ap1",
            "20261008-x-ap2",
            "notes",
        ]
    );
    assert!(outside.join("MANIFEST").exists());
    assert!(
        said(&out).contains(".20261000-deep-ap2.pruning: it holds more than files; left"),
        "{}",
        said(&out)
    );
}

/// The build user's stamps and images are read as root without following a
/// link or waiting on a FIFO: a FIFO and a link for stamps are taken as
/// missing (so what the AP runs is not known, and nothing is pruned), and
/// a tree or images/ that is a link is refused; a leftover of an
/// interrupted prune goes, and nothing a prune is removing stays under an
/// image's name.
#[test]
fn a_tree_of_the_wrong_shape_is_read_safely() {
    let t = checkout("prune-shape");
    let dir = &t.0;
    for n in 1..=5 {
        keep(dir, &format!("2026100{n}-x-ap1"), "ap1");
    }
    let fifo = std::ffi::CString::new(
        dir.join("stamps/running-ap1")
            .into_os_string()
            .into_encoded_bytes(),
    )
    .unwrap();
    // SAFETY: a valid path, mode as for any file.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
    fs::write(dir.join("elsewhere"), "k1 images/20261001-x-ap1\n").unwrap();
    std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("stamps/built-ap1")).unwrap();
    fs::write(dir.join("stamps/ap-ap1"), "k1\n").unwrap();
    let started = std::time::Instant::now();
    let out = run(dir, "U6E_APS=ap1; prune_images");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("what ap1 runs is not known"),
        "{}",
        said(&out)
    );
    assert_eq!(left(dir).len(), 5);

    // A tree, or its images/, that is a link: refused, nothing read there.
    let link = dir.join("tree-link");
    std::os::unix::fs::symlink(dir, &link).unwrap();
    let out = run(
        dir,
        &format!("U6E_APS=ap1; prune_images {}", link.display()),
    );
    assert!(said(&out).contains("none pruned"), "{}", said(&out));
    assert_eq!(left(dir).len(), 5);

    // The stamps right, and the leftover of an interrupted prune.
    fs::remove_file(dir.join("stamps/running-ap1")).unwrap();
    fs::write(dir.join("stamps/running-ap1"), "20261001-x-ap1\n").unwrap();
    keep(dir, "20261000-half-ap1", "ap1");
    fs::rename(
        dir.join("images/20261000-half-ap1"),
        dir.join("images/.20261000-half-ap1.pruning"),
    )
    .unwrap();
    let out = run(dir, "U6E_APS=ap1; prune_images");
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        left(dir),
        [
            "20261001-x-ap1",
            "20261003-x-ap1",
            "20261004-x-ap1",
            "20261005-x-ap1"
        ]
    );
}

/// Nothing is pruned while what an AP runs is not known, or the runner
/// does not answer.
#[test]
fn pruning_waits_for_what_it_must_know() {
    let t = checkout("prune-unknown");
    let dir = &t.0;
    for n in 1..=6 {
        keep(dir, &format!("2026100{n}-x-ap1"), "ap1");
    }
    fs::write(dir.join("stamps/built-ap1"), "k1 images/20261006-x-ap1\n").unwrap();
    // ap1 runs an older build than the current one, and nothing says which.
    fs::write(dir.join("stamps/ap-ap1"), "k0\n").unwrap();
    let out = run(dir, "U6E_APS=ap1; prune_images");
    assert!(
        said(&out).contains("what ap1 runs is not known"),
        "{}",
        said(&out)
    );
    assert_eq!(left(dir).len(), 6);
    fs::write(dir.join("stamps/running-ap1"), "20261001-x-ap1\n").unwrap();
    let out = run(
        dir,
        "U6E_APS=ap1; runner_images() { return 1; }; prune_images",
    );
    assert!(
        said(&out).contains("did not say which images it needs"),
        "{}",
        said(&out)
    );
    assert_eq!(left(dir).len(), 6);
    let out = run(dir, "U6E_APS=ap1; prune_images");
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        left(dir),
        [
            "20261001-x-ap1",
            "20261004-x-ap1",
            "20261005-x-ap1",
            "20261006-x-ap1"
        ]
    );
}

/// With less room than MIN_FREE_GIB on the tree's filesystem, deploy.sh
/// stops before it builds anything.
#[test]
fn nothing_is_built_without_room() {
    let t = checkout("room");
    let dir = &t.0;
    fs::write(dir.join("site.conf"), "").unwrap();
    fs::write(dir.join("toolchain.env"), "").unwrap();
    let out = Command::new("bash")
        .arg("deploy.sh")
        .env("MIN_FREE_GIB", "999999")
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let said = said(&out);
    assert!(said.starts_with("only "), "{said}");
    assert!(
        said.contains("less than the 999999 GiB a build may take"),
        "{said}"
    );
    assert!(!dir.join("dl").exists() && !dir.join("log/trees.log").exists());
}

/// Another tree's images are pruned by this checkout's rule and script,
/// never by that tree's own (here one that would record its run).
#[test]
fn another_tree_is_pruned_by_this_checkouts_rule() {
    let t = checkout("prune-own");
    let other = checkout("prune-other");
    let (dir, theirs) = (&t.0, &other.0);
    for n in 1..=5 {
        keep(theirs, &format!("2026100{n}-x-ap1"), "ap1");
    }
    fs::write(theirs.join("stamps/running-ap1"), "20261001-x-ap1\n").unwrap();
    let ran = theirs.join("theirs-ran");
    fs::write(
        theirs.join("prune-images.py"),
        format!("open('{}', 'w').write('ran')\n", ran.display()),
    )
    .unwrap();
    let out = run(
        dir,
        &format!("U6E_APS=ap1; prune_images {}", theirs.display()),
    );
    assert!(out.status.success(), "{}", said(&out));
    assert!(!ran.exists());
    assert_eq!(
        left(theirs),
        [
            "20261001-x-ap1",
            "20261003-x-ap1",
            "20261004-x-ap1",
            "20261005-x-ap1"
        ]
    );
}

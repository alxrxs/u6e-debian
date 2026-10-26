//! deploy.sh's boot of an access point (`ap-image.sh`'s `boot_ap`) and the
//! deploy runner: what it stages, it tells the runner (site.conf's
//! `runner_staged`) before it takes the boot as done, so a runner it could
//! not tell is told by the next run, which stages the image again. Run with
//! a staging that only logs and an AP whose radios are always up.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory of the test's own, removed when it ends.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A checkout's worth of what `boot_ap` needs: ap-image.sh as the
/// repository has it, a kept image built for the inputs `key1`, and a
/// staging that logs what it boots.
fn checkout() -> TempDir {
    let dir = std::env::temp_dir().join(format!("u6e-boot-ap-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("boot")).unwrap();
    fs::create_dir_all(dir.join("stamps")).unwrap();
    fs::create_dir_all(dir.join("images/img-7-ap1")).unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::copy(repo.join("ap-image.sh"), dir.join("ap-image.sh")).unwrap();
    fs::write(dir.join("images/img-7-ap1/MANIFEST"), "ap:        ap1\n").unwrap();
    let built = format!("key1 {}\n", dir.join("images/img-7-ap1").display());
    fs::write(dir.join("stamps/built-ap1"), built).unwrap();
    fs::write(
        dir.join("boot/stage.sh"),
        "#!/bin/sh\necho \"staged ${1##*/}\" >> \"$(dirname \"$0\")/../events\"\n",
    )
    .unwrap();
    fs::write(dir.join("boot/lib.sh"), "ap_root() { echo 3; }\n").unwrap();
    let mode = std::os::unix::fs::PermissionsExt::from_mode(0o755);
    fs::set_permissions(dir.join("boot/stage.sh"), mode).unwrap();
    TempDir(dir)
}

/// Runs `boot_ap ap1 key1` in `dir` with a runner that takes the word only
/// once `tell-ok` exists; whether it succeeded.
fn boot(dir: &Path) -> bool {
    let script = "fail() { echo \"$*\" >&2; exit 1; }; L=log; . ./ap-image.sh
        runner_staged() { echo \"told $1 $2\" >> events; [ -e tell-ok ]; }
        boot_ap ap1 key1";
    let out = Command::new("bash")
        .args(["-c", script])
        .current_dir(dir)
        .output()
        .unwrap();
    out.status.success()
}

fn events(dir: &Path) -> Vec<String> {
    let text = fs::read_to_string(dir.join("events")).unwrap_or_default();
    text.lines().map(str::to_owned).collect()
}

#[test]
fn a_boot_the_runner_was_not_told_of_is_not_taken_as_done() {
    let t = checkout();
    let dir = &t.0;
    // The runner is down: the AP was booted, the run fails, and no stamp
    // says the AP runs it.
    assert!(!boot(dir));
    assert_eq!(events(dir), ["staged img-7-ap1", "told ap1 img-7-ap1"]);
    assert!(!dir.join("stamps/ap-ap1").exists());
    // The next run stages it again and tells the runner, which takes it.
    fs::write(dir.join("tell-ok"), "").unwrap();
    assert!(boot(dir));
    assert_eq!(events(dir)[2..], ["staged img-7-ap1", "told ap1 img-7-ap1"]);
    assert_eq!(
        fs::read_to_string(dir.join("stamps/ap-ap1")).unwrap(),
        "key1\n"
    );
    // Done: a run after it stages nothing and tells nothing.
    assert!(boot(dir));
    assert_eq!(events(dir).len(), 4);
}

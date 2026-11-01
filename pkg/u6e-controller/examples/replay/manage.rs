//! What the replay's controller manages: its signing key, and kept images
//! of each AP, made afresh in the temporary directory at each start, a
//! newer one than each AP runs among them. A staging is made up too
//! (`SimStage`): it takes a few seconds and has the AP drop its link and
//! come back with the image, except one named `-bad-`, which leaves the AP
//! on its old image, so its gate fails and it is rolled back.

use std::fmt::Write as _;
use std::fs;
use std::future::Future;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::digest;
use tokio::time::sleep;
use u6e_controller::images::{Kept, PAYLOADS};
use u6e_controller::stage::{Log, Stage, Staged, Target};
use u6e_proto::mac;

use crate::World;
use crate::keys::KEY_SIGNING;

/// How long a staging takes, and the link stays down after it.
const STAGING: Duration = Duration::from_secs(4);
const REBOOT_S: f64 = 15.0;

/// The images each AP gets: what it runs, and a newer one.
pub const IMAGES: [(&str, &str); 4] = [
    ("ap1", "20261024-213000-5f0c2a1-9e1d3b7-ap1"),
    ("ap1", "20261031-090000-6a1b2c3-9e1d3b7-ap1"),
    ("ap2", "20261019-090500-c41d77e-2b80f15-ap2"),
    ("ap2", "20261031-090100-6a1b2c3-bad-ap2"),
];

fn write(path: &Path, body: &[u8], mode: u32) -> io::Result<()> {
    fs::write(path, body)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// The `[configs]` and `[rollouts]` of the replay's configuration, their
/// files made in `dir`.
pub fn sections(dir: &Path) -> io::Result<String> {
    let _ = fs::remove_dir_all(dir);
    let images = dir.join("images");
    fs::create_dir_all(&images)?;
    for (ap, id) in IMAGES {
        let image = images.join(id);
        fs::create_dir_all(&image)?;
        let mut manifest = format!("ap:        {ap} (u6e-{ap}, 192.0.2.16/24)\n");
        for name in PAYLOADS {
            let body = format!("{name} of {id}");
            write(&image.join(name), body.as_bytes(), 0o600)?;
            let sha = digest::digest(&digest::SHA256, body.as_bytes());
            let _ = writeln!(manifest, "{}  out/{name}", mac::hex(sha.as_ref()));
        }
        write(&image.join("MANIFEST"), manifest.as_bytes(), 0o600)?;
    }
    for (name, body) in [
        ("signing-key.pem", KEY_SIGNING),
        ("ap-root-key", ""),
        ("ap-pw", ""),
        ("ap-hosts", ""),
    ] {
        write(&dir.join(name), body.as_bytes(), 0o600)?;
    }
    let d = dir.display();
    Ok(format!(
        "[configs]\nsigning_key = \"{d}/signing-key.pem\"\nstate = \"{d}/configs\"\n\
         [rollouts]\nimages = \"{d}/images\"\ngate_secs = 60\nroot_key = \"{d}/ap-root-key\"\n\
         stock_password = \"{d}/ap-pw\"\nknown_hosts = \"{d}/ap-hosts\"\n"
    ))
}

/// The made-up staging.
pub struct SimStage(pub Arc<Mutex<World>>);

impl Stage for SimStage {
    fn stage<'a>(
        &'a self,
        target: &'a Target,
        image: &'a Kept,
        log: Log<'a>,
    ) -> Pin<Box<dyn Future<Output = Staged> + Send + 'a>> {
        Box::pin(async move {
            log(format!("{}: disarmed, rebooting into stock", target.ap));
            sleep(STAGING / 2).await;
            for name in ["u6e.zimg", "u6e.dtb", "u6e.initrd", "u6e.k64"] {
                log(format!("{name}: 64 of 64 KiB written, 1 extent(s)"));
            }
            sleep(STAGING / 2).await;
            log(format!("{}: rebooting into {}", target.ap, image.id));
            let mut w = self.0.lock().unwrap_or_else(|e| e.into_inner());
            w.reboot(&target.ap, &image.id, REBOOT_S);
            Staged::Done
        })
    }
}

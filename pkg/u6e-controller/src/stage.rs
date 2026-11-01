//! Staging a kept image on an AP: what u6e-debian's `boot/stage.sh` does,
//! with `boot/go8.sh` and `boot/ext4map.py`, done by the controller itself,
//! as its own unprivileged user, over SSH with the credentials it holds
//! (`[rollouts]`): the image's root key and the stock firmware's password,
//! each host key checked against its own known_hosts (the image's under the
//! AP's host name, stock's, which answers on the same address, under
//! `<host name>-stock`, as `boot/lib.sh` checks them). Every command it runs
//! there is one of a fixed few, with only numbers and names it made itself
//! in it, and each has a time bound past which its process group is killed.
//!
//! From the AP's image, it disarms the next boot and reboots into stock;
//! there, each of the image's four files becomes a file in stock's
//! `/tmp/log` (ext4 on the eMMC), of which only the 64 KiB chunks that differ
//! from what is there already are written, each run through stock's RAM, and
//! checked by their SHA-256 after; the file's extents (read from the ext4
//! structures on the partition) become U-Boot `mmc read`s, each payload
//! CRC-gated, and one `fw_setenv` arms a boot that disarms itself first.
//! Stock reboots into the image, and the staging ends once the image's SSH
//! answers. `Ssh` is that; a test stages through a `Stage` of its own. The
//! tests hold the env and the extents to what `go8.sh` and `ext4map.py`
//! make of the same inputs, so a change to either shows here.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use u6e_proto::mac;

use crate::images::Kept;

/// An AP as a staging reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ap: String,
    /// The name both host keys are checked under.
    pub hostname: String,
    /// The address both of its systems answer SSH on.
    pub address: String,
}

/// How a staging ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staged {
    Done,
    /// Nothing was done to the AP (it answered neither system): why.
    Untouched(String),
    /// It failed part way: the AP may be anywhere between its two systems.
    Failed(String),
}

/// Where a staging's lines go.
pub type Log<'a> = &'a (dyn Fn(String) + Send + Sync);

/// What stages an image on an AP.
pub trait Stage: Send + Sync {
    fn stage<'a>(
        &'a self,
        target: &'a Target,
        image: &'a Kept,
        log: Log<'a>,
    ) -> Pin<Box<dyn Future<Output = Staged> + Send + 'a>>;
}

/// The credentials a staging logs in with, each a file of the controller's
/// user alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The private key the images' root accepts.
    pub root_key: PathBuf,
    /// The stock firmware's user (its "device authentication" one).
    pub stock_user: String,
    /// A file holding that user's password, which `sshpass -f` reads.
    pub stock_password: PathBuf,
    /// The APs' host keys, as `boot/lib.sh` names them.
    pub known_hosts: PathBuf,
}

/// Where stock keeps the payloads, between stagings too.
const STAGE_DIR: &str = "/tmp/log/.u6e";
/// What is compared and written at a time: a changed DTB or script costs
/// 64 KiB, not more.
const CHUNK: usize = 65536;
/// The most chunks one write carries (through stock's RAM).
const RUN_MAX: usize = 256;
/// The names the payloads have on stock, each with its file of the image
/// and the address U-Boot loads it at.
const STAGED: [(&str, &str, u64); 4] = [
    ("u6e.zimg", "shim.bin", 0x4400_0000),
    ("u6e.dtb", "u6e.dtb", 0x47f0_0000),
    ("u6e.initrd", "u6e.initrd", 0x5220_0000),
    ("u6e.k64", "Image", 0x4100_0000),
];
/// Where U-Boot keeps each payload's CRC, 0x10 apart.
const CRC_SCRATCH: u64 = 0x4f00_0000;
/// The env names earlier staging schemes left behind, deleted by naming them.
const STALE: &str = "z8r0 z8r1 z8r2 z8r3 z8crc d8r0 d8r1 d8crc i8r0 i8r1 i8r2 i8r3 i8r4 i8r5 \
                     i8crc k8r0 k8r1 k8r2 k8r3 k8crc u8z u8d u8i u8k c8go c8ret";
/// The partition stock's /tmp/log is on.
const PARTITION: &str = "/dev/mmcblk0p5";

/// How long the steps of a staging may take.
#[derive(Debug, Clone, Copy)]
pub struct Waits {
    /// After a reboot is asked for, before the AP is looked at again.
    pub settle: Duration,
    /// How long the AP may take to answer as stock, and as its image.
    pub stock: Duration,
    pub image: Duration,
    /// Between two looks.
    pub poll: Duration,
}

impl Default for Waits {
    fn default() -> Self {
        Waits {
            settle: Duration::from_secs(30),
            stock: Duration::from_secs(400),
            image: Duration::from_secs(600),
            poll: Duration::from_secs(10),
        }
    }
}

/// The AP's two systems, as they answer SSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum System {
    /// The image, its root by key.
    Image,
    /// The stock firmware, by password.
    Stock,
}

/// The staging over SSH.
pub struct Ssh {
    creds: Credentials,
    waits: Waits,
    /// The programs it runs: OpenSSH's client, and `sshpass` around it for
    /// stock's password.
    ssh: PathBuf,
    sshpass: PathBuf,
}

impl Stage for Ssh {
    fn stage<'a>(
        &'a self,
        target: &'a Target,
        image: &'a Kept,
        log: Log<'a>,
    ) -> Pin<Box<dyn Future<Output = Staged> + Send + 'a>> {
        Box::pin(self.staged(target, image, log))
    }
}

impl Ssh {
    pub fn new(creds: Credentials, waits: Waits) -> Ssh {
        Ssh {
            creds,
            waits,
            ssh: "ssh".into(),
            sshpass: "sshpass".into(),
        }
    }

    async fn staged(&self, t: &Target, image: &Kept, log: Log<'_>) -> Staged {
        let Some(now) = self.system(t).await else {
            return Staged::Untouched(format!("{} answers neither its image nor stock", t.ap));
        };
        let r = async {
            if now == System::Image {
                // The session dies with the reboot, so its status says nothing.
                let disarm = "/usr/local/sbin/u6e-arm disarm && systemctl reboot";
                let _ = self.run(t, System::Image, disarm, None, secs(20)).await;
                log(format!("{}: disarmed, rebooting into stock", t.ap));
                sleep(self.waits.settle).await;
                self.wait_for(t, System::Stock, self.waits.stock, log)
                    .await?;
            }
            self.go8(t, image, log).await?;
            let _ = self.run(t, System::Stock, "reboot", None, secs(20)).await;
            log(format!("{}: rebooting into {}", t.ap, image.id));
            sleep(self.waits.settle).await;
            self.wait_for(t, System::Image, self.waits.image, log).await
        };
        match r.await {
            Ok(()) => Staged::Done,
            Err(why) => Staged::Failed(why),
        }
    }

    /// The system the AP answers as, if any.
    async fn system(&self, t: &Target) -> Option<System> {
        for s in [System::Image, System::Stock] {
            if self.run(t, s, "true", None, secs(10)).await.is_ok() {
                return Some(s);
            }
        }
        None
    }

    async fn wait_for(
        &self,
        t: &Target,
        want: System,
        within: Duration,
        log: Log<'_>,
    ) -> Result<(), String> {
        let (started, what) = (
            Instant::now(),
            match want {
                System::Image => "its image",
                System::Stock => "stock",
            },
        );
        loop {
            if self.system(t).await == Some(want) {
                let s = started.elapsed().as_secs();
                log(format!("{}: in {what} after {s} s", t.ap));
                return Ok(());
            }
            if started.elapsed() >= within {
                return Err(format!(
                    "{} not in {what} after {} s",
                    t.ap,
                    within.as_secs()
                ));
            }
            sleep(self.waits.poll).await;
        }
    }

    /// The ssh command of `system` on `t`, `cmd` run there.
    fn command(&self, t: &Target, system: System, cmd: &str) -> Command {
        let c = &self.creds;
        let mut ssh = match system {
            System::Image => Command::new(&self.ssh),
            System::Stock => {
                let mut s = Command::new(&self.sshpass);
                s.arg("-f").arg(&c.stock_password).arg(&self.ssh);
                s
            }
        };
        let mut opt = |o: String| {
            ssh.arg("-o").arg(o);
        };
        opt("LogLevel=ERROR".into());
        opt("ConnectTimeout=5".into());
        opt("StrictHostKeyChecking=yes".into());
        opt(format!("UserKnownHostsFile={}", c.known_hosts.display()));
        opt("GlobalKnownHostsFile=/dev/null".into());
        let login = match system {
            System::Image => {
                opt(format!("HostKeyAlias={}", t.hostname));
                opt("BatchMode=yes".into());
                opt("IdentitiesOnly=yes".into());
                opt(format!("IdentityFile={}", c.root_key.display()));
                format!("root@{}", t.address)
            }
            System::Stock => {
                opt(format!("HostKeyAlias={}-stock", t.hostname));
                opt("PubkeyAuthentication=no".into());
                format!("{}@{}", c.stock_user, t.address)
            }
        };
        ssh.args(["-F", "/dev/null", "--", &login, cmd]);
        ssh
    }

    /// Runs `cmd` on `system`, `input` its stdin, within `within`; its
    /// stdout, or why it failed.
    async fn run(
        &self,
        t: &Target,
        system: System,
        cmd: &str,
        input: Option<Vec<u8>>,
        within: Duration,
    ) -> Result<Vec<u8>, String> {
        let mut c = self.command(t, system, cmd);
        c.process_group(0)
            .kill_on_drop(true)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run(c, input, within).await
    }

    /// Stages each payload and arms the boot (`go8.sh`), from stock.
    async fn go8(&self, t: &Target, image: &Kept, log: Log<'_>) -> Result<(), String> {
        let part_start = self
            .run(
                t,
                System::Stock,
                "cat /sys/block/mmcblk0/mmcblk0p5/start",
                None,
                secs(60),
            )
            .await?;
        let part_start: u64 = String::from_utf8_lossy(&part_start)
            .trim()
            .parse()
            .map_err(|_| "the partition's start is not a number")?;
        let mut loads = Vec::new();
        for (name, file, base) in STAGED {
            let extents = self
                .payload(t, name, &image.file(file), part_start, log)
                .await?;
            let bytes = std::fs::read(image.file(file)).map_err(|e| format!("{file}: {e}"))?;
            loads.push(Load {
                base,
                size: bytes.len() as u64,
                crc: crc32(&bytes),
                extents,
            });
        }
        let env = env(&loads)?;
        self.run(
            t,
            System::Stock,
            "fw_setenv -s -",
            Some(env.into_bytes()),
            secs(60),
        )
        .await?;
        let armed = self
            .run(t, System::Stock, "fw_printenv bootcmd_real", None, secs(60))
            .await?;
        log(format!(
            "{}: armed {}",
            t.ap,
            String::from_utf8_lossy(&armed).trim()
        ));
        Ok(())
    }

    /// The SHA-256 of each of the first `chunks` chunks of `name` on stock.
    async fn staged_hashes(
        &self,
        t: &Target,
        name: &str,
        chunks: usize,
    ) -> Result<Vec<String>, String> {
        let cmd = format!(
            "for i in $(seq 0 {}); do dd if={STAGE_DIR}/{name} bs={CHUNK} skip=$i count=1 \
             2>/dev/null | sha256sum | cut -c1-64; done",
            chunks as i64 - 1
        );
        let out = self.run(t, System::Stock, &cmd, None, secs(120)).await?;
        let text = String::from_utf8_lossy(&out);
        Ok(text.lines().map(str::to_owned).collect())
    }

    /// Makes `name` on stock the file at `path`, padded to whole chunks,
    /// writing only the chunks that differ; its extents.
    async fn payload(
        &self,
        t: &Target,
        name: &str,
        path: &Path,
        part_start: u64,
        log: Log<'_>,
    ) -> Result<Vec<Extent>, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let padded = pad(bytes);
        let chunks = padded.len() / CHUNK;
        let want: Vec<String> = padded
            .chunks(CHUNK)
            .map(|c| mac::hex(digest::digest(&digest::SHA256, c).as_ref()))
            .collect();
        let mkdir = format!("mkdir -p {STAGE_DIR}");
        self.run(t, System::Stock, &mkdir, None, secs(60)).await?;
        let have = self.staged_hashes(t, name, chunks).await?;
        let mut written = 0;
        for (start, len) in runs(&want, &have) {
            let cmd = format!(
                "cat > /tmp/u6e-chunk && dd if=/tmp/u6e-chunk of={STAGE_DIR}/{name} bs={CHUNK} \
                 seek={start} conv=notrunc,fsync 2>/dev/null; rc=$?; rm -f /tmp/u6e-chunk; exit $rc"
            );
            let part = padded[start * CHUNK..(start + len) * CHUNK].to_vec();
            self.run(t, System::Stock, &cmd, Some(part), secs(300))
                .await
                .map_err(|e| format!("{name}: {e}"))?;
            written += len;
        }
        // A longer earlier payload is cut back: U-Boot reads every extent.
        let cut = format!(
            "dd if=/dev/null of={STAGE_DIR}/{name} bs={CHUNK} seek={chunks} 2>/dev/null && sync"
        );
        self.run(t, System::Stock, &cut, None, secs(60)).await?;
        if self.staged_hashes(t, name, chunks).await? != want {
            return Err(format!("{name}: verify failed"));
        }
        let ls = format!("ls -i {STAGE_DIR}/{name}");
        let ls = self.run(t, System::Stock, &ls, None, secs(60)).await?;
        let ino = String::from_utf8_lossy(&ls)
            .split_whitespace()
            .next()
            .and_then(|i| i.parse().ok())
            .ok_or_else(|| format!("{name}: no inode"))?;
        let mut disk = StockDisk { ssh: self, t };
        let extents = map(&mut disk, part_start, ino)
            .await
            .map_err(|e| format!("{name}: {e}"))?;
        log(format!(
            "{name}: {} of {} KiB written, {} extent(s)",
            written * CHUNK / 1024,
            chunks * CHUNK / 1024,
            extents.len()
        ));
        Ok(extents)
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Runs `c`, `input` its stdin, within `within`, killing its process group
/// past it; its stdout, or why it failed (its exit and stderr's last line).
async fn run(mut c: Command, input: Option<Vec<u8>>, within: Duration) -> Result<Vec<u8>, String> {
    let mut child = c.spawn().map_err(|e| format!("ssh: {e}"))?;
    let group = child.id();
    let stdin = child.stdin.take();
    let (mut stdout, mut stderr) = (child.stdout.take(), child.stderr.take());
    let work = async {
        let feed = async {
            if let (Some(mut s), Some(bytes)) = (stdin, input) {
                // A command that ends early says why on stderr.
                let _ = s.write_all(&bytes).await;
            }
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let read = async {
            if let Some(o) = stdout.as_mut() {
                let _ = o.read_to_end(&mut out).await;
            }
        };
        let read_err = async {
            if let Some(e) = stderr.as_mut() {
                let _ = e.read_to_end(&mut err).await;
            }
        };
        let ((), (), ()) = tokio::join!(feed, read, read_err);
        let status = child.wait().await;
        (status, out, err)
    };
    match timeout(within, work).await {
        Ok((Ok(status), out, _)) if status.success() => Ok(out),
        Ok((Ok(status), _, err)) => {
            let err = String::from_utf8_lossy(&err);
            let last = err.lines().last().unwrap_or_default().to_owned();
            Err(format!("{status}: {last:.200}"))
        }
        Ok((Err(e), _, _)) => Err(e.to_string()),
        Err(_) => {
            if let Some(pid) = group.and_then(|p| i32::try_from(p).ok()) {
                // SAFETY: a signal to the command's own process group.
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
            Err(format!("no end in {within:?}"))
        }
    }
}

/// `bytes`, padded with zeros to whole chunks.
fn pad(mut bytes: Vec<u8>) -> Vec<u8> {
    let len = bytes.len().div_ceil(CHUNK) * CHUNK;
    bytes.resize(len, 0);
    bytes
}

/// The runs of chunks whose hashes differ from those staged (`have`, which
/// may be short), each `(first, count)` and no longer than [`RUN_MAX`].
fn runs(want: &[String], have: &[String]) -> Vec<(usize, usize)> {
    let differs = |i: usize| have.get(i) != Some(&want[i]);
    let (mut out, mut i) = (Vec::new(), 0);
    while i < want.len() {
        if !differs(i) {
            i += 1;
            continue;
        }
        let s = i;
        while i < want.len() && i - s < RUN_MAX && differs(i) {
            i += 1;
        }
        out.push((s, i - s));
    }
    out
}

/// What a disk read takes: `n` bytes at `off`.
trait Disk {
    fn read(&mut self, off: u64, n: usize) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

/// The partition as stock reads it, 512 B sectors at a time.
struct StockDisk<'a> {
    ssh: &'a Ssh,
    t: &'a Target,
}

impl Disk for StockDisk<'_> {
    async fn read(&mut self, off: u64, n: usize) -> Result<Vec<u8>, String> {
        let skip = off / 512;
        let count = (off + n as u64).div_ceil(512) - skip;
        let cmd = format!("dd if={PARTITION} bs=512 skip={skip} count={count} 2>/dev/null");
        let out = self
            .ssh
            .run(self.t, System::Stock, &cmd, None, secs(60))
            .await?;
        let s = (off - skip * 512) as usize;
        out.get(s..s + n)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| "a short read of the partition".into())
    }
}

/// One extent of a file, as U-Boot reads it from the eMMC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub disk_sector: u64,
    pub sectors: u64,
}

fn u16_at(b: &[u8], o: usize) -> u64 {
    u64::from(u16::from_le_bytes([b[o], b[o + 1]]))
}

fn u32_at(b: &[u8], o: usize) -> u64 {
    u64::from(u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]))
}

/// The extents of inode `ino` of the ext4 file system on the partition that
/// starts at sector `part_start` (`boot/ext4map.py`), in file order, with
/// no hole between them.
async fn map(disk: &mut impl Disk, part_start: u64, ino: u64) -> Result<Vec<Extent>, String> {
    let sb = disk.read(1024, 1024).await?;
    if u16_at(&sb, 0x38) != 0xEF53 {
        return Err("not ext4".into());
    }
    let bsz = 1024u64 << u32_at(&sb, 24);
    let (ipg, isz, fdb) = (u32_at(&sb, 40), u16_at(&sb, 88), u32_at(&sb, 20));
    let is64 = u32_at(&sb, 96) & 0x80 != 0;
    let dsz = if is64 { u16_at(&sb, 254) } else { 32 };
    if ipg == 0 || ino == 0 || isz < 0x28 + 60 {
        return Err("not an inode of this file system".into());
    }
    let (g, idx) = ((ino - 1) / ipg, (ino - 1) % ipg);
    let gd = disk.read((fdb + 1) * bsz + g * dsz, dsz as usize).await?;
    let mut itab = u32_at(&gd, 8);
    if is64 && dsz >= 64 {
        itab |= u32_at(&gd, 0x28) << 32;
    }
    let inode = disk.read(itab * bsz + idx * isz, isz as usize).await?;
    if u32_at(&inode, 0x20) & 0x80000 == 0 {
        return Err("not extent-mapped".into());
    }
    let mut leaves: Vec<(u64, u64, u64)> = Vec::new();
    let mut nodes = vec![inode[0x28..0x28 + 60].to_vec()];
    while let Some(node) = nodes.pop() {
        if node.len() < 12 || u16_at(&node, 0) != 0xF30A {
            return Err("not an extent node".into());
        }
        let (n, depth) = (u16_at(&node, 2) as usize, u16_at(&node, 6));
        for i in 0..n {
            let e = node
                .get(12 + 12 * i..24 + 12 * i)
                .ok_or("an extent node longer than its block")?;
            if depth == 0 {
                let (lblk, len) = (u32_at(e, 0), u16_at(e, 4));
                if len > 32768 {
                    return Err("an unwritten extent".into());
                }
                leaves.push((lblk, (u16_at(e, 6) << 32) | u32_at(e, 8), len));
            } else {
                let child = (u16_at(e, 8) << 32) | u32_at(e, 4);
                nodes.push(disk.read(child * bsz, bsz as usize).await?);
            }
        }
    }
    leaves.sort();
    let mut next = 0;
    let mut out = Vec::new();
    for (lblk, pblk, len) in leaves {
        if lblk != next {
            return Err("a hole in the file".into());
        }
        next += len;
        out.push(Extent {
            disk_sector: part_start + pblk * bsz / 512,
            sectors: len * bsz / 512,
        });
    }
    Ok(out)
}

/// A payload as U-Boot loads it: where, how long it is, its CRC-32, and
/// its extents.
struct Load {
    base: u64,
    size: u64,
    crc: u32,
    extents: Vec<Extent>,
}

/// zlib's CRC-32, which U-Boot's `crc32` computes.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// The `fw_setenv -s` script that arms the boot of `loads` (`go8.sh`'s): each
/// payload read to consecutive RAM and CRC-checked, then, every check
/// passing, `bootz` of the first (the arm64 shim, which enters the Image),
/// else stock (`bootubnt`); `bootcmd_real` puts itself back to stock first,
/// so the boot happens once.
fn env(loads: &[Load]) -> Result<String, String> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut gates = Vec::new();
    for (i, l) in loads.iter().enumerate() {
        let slot = CRC_SCRATCH + 0x10 * i as u64;
        let mut addr = l.base;
        let mut cmds = Vec::new();
        for e in &l.extents {
            cmds.push(format!(
                "mmc read {addr:#x} {:#x} {:#x};",
                e.disk_sector, e.sectors
            ));
            addr += e.sectors * 512;
        }
        let cmd = format!(
            "{} crc32 {:#x} {:#x} {slot:#x}",
            cmds.join(" "),
            l.base,
            l.size
        );
        // crc32 stores big-endian; itest reads the slot as a native (LE) long.
        let want = l.crc.swap_bytes();
        gates.push(format!("itest *{slot:#x} == {want:#x}"));
        env.push((format!("u8{i}"), cmd));
    }
    let (za, da) = (loads[0].base, loads[1].base);
    let mut boot: String = gates.iter().map(|g| format!("if {g}; then ")).collect();
    boot += &format!("bootz {za:#x} - {da:#x}; ");
    boot += &"fi; ".repeat(gates.len());
    boot += "bootubnt";
    env.push(("u8b".into(), boot));
    let runs: String = (0..loads.len()).map(|i| format!("run u8{i}; ")).collect();
    env.push((
        "bootcmd_real".into(),
        format!("setenv bootcmd_real bootubnt; saveenv; {runs}run u8b"),
    ));
    let mut out = String::new();
    for k in STALE.split_whitespace() {
        if env.iter().all(|(n, _)| n != k) {
            out += &format!("{k}\n");
        }
    }
    for (k, v) in &env {
        if v.len() >= 1000 {
            return Err(format!("{k} too long ({})", v.len()));
        }
        out += &format!("{k} {v}\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command as Std;

    use crate::testdir::TestDir;

    fn hashes(n: &[u8]) -> Vec<String> {
        n.iter().map(|b| format!("{b:064x}")).collect()
    }

    #[test]
    fn only_the_chunks_that_differ_are_written() {
        let want = hashes(&[1, 2, 3, 4, 5]);
        assert_eq!(runs(&want, &want), []);
        assert_eq!(runs(&want, &[]), [(0, 5)]);
        assert_eq!(runs(&want, &hashes(&[1, 9, 9, 4])), [(1, 2), (4, 1)]);
        let long = hashes(&[7; 300]);
        assert_eq!(runs(&long, &[]), [(0, 256), (256, 44)]);
        assert_eq!(pad(vec![1; CHUNK + 1]).len(), 2 * CHUNK);
        assert_eq!(pad(vec![1; CHUNK]).len(), CHUNK);
    }

    #[test]
    fn crc32_is_zlibs() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// A tool of the build host, or why the test cannot run.
    fn tool(name: &str) -> bool {
        let found = Std::new("sh")
            .args(["-c", &format!("command -v {name}")])
            .output()
            .is_ok_and(|o| o.status.success());
        if !found {
            eprintln!("{name} not found: the comparison with u6e-debian's own script is skipped");
        }
        found
    }

    /// The env of go8.sh's own Python, for the same files and extents.
    fn go8_env(dir: &Path, files: &[PathBuf], maps: &[Vec<Extent>]) -> String {
        let go8 =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../boot/go8.sh"))
                .unwrap();
        let start = go8.find("<<'PY'\n").unwrap() + 7;
        let len = go8[start..].find("\nPY\n").unwrap();
        fs::write(dir.join("go8.py"), &go8[start..start + len]).unwrap();
        for ((name, _, _), extents) in STAGED.iter().zip(maps) {
            let mut text = format!("size=0 blocksize=4096 inode=12 extents={}\n", extents.len());
            for e in extents {
                text += &format!(
                    "EXT logical=0 phys_block=0 blocks=0 disk_sector={} sectors={}\n",
                    e.disk_sector, e.sectors
                );
            }
            fs::write(dir.join(format!("map_{name}")), text).unwrap();
        }
        let mut py = Std::new("python3");
        py.arg("-I").arg(dir.join("go8.py")).arg(dir).args(files);
        py.args([
            "0x44000000",
            "0x47f00000",
            "0x52200000",
            "0x41000000",
            "0x4f000000",
        ]);
        assert!(py.output().unwrap().status.success());
        fs::read_to_string(dir.join("env")).unwrap()
    }

    /// The env is go8.sh's, byte for byte.
    #[test]
    fn the_env_is_go8s() {
        if !tool("python3") {
            return;
        }
        let t = TestDir::new();
        let mut files = Vec::new();
        let mut loads = Vec::new();
        let mut maps = Vec::new();
        for (i, (_, file, base)) in STAGED.iter().enumerate() {
            let bytes: Vec<u8> = (0..(1000 + i * 70_000))
                .map(|n| (n * 7 + i) as u8)
                .collect();
            let path = t.path().join(file);
            fs::write(&path, &bytes).unwrap();
            let extents: Vec<Extent> = (0..=i as u64)
                .map(|k| Extent {
                    disk_sector: 0x1_0000 + 0x800 * k + i as u64,
                    sectors: 8 * (k + 1),
                })
                .collect();
            files.push(path);
            maps.push(extents.clone());
            loads.push(Load {
                base: *base,
                size: bytes.len() as u64,
                crc: crc32(&bytes),
                extents,
            });
        }
        let ours = env(&loads).unwrap();
        // The Python prints the env too, and writes it to `env`.
        assert_eq!(ours, go8_env(t.path(), &files, &maps));
        assert!(ours.contains("bootcmd_real setenv bootcmd_real bootubnt; saveenv; run u80;"));
    }

    /// A disk image's file as `Disk` reads it.
    struct Image(Vec<u8>);

    impl Disk for Image {
        async fn read(&mut self, off: u64, n: usize) -> Result<Vec<u8>, String> {
            let off = off as usize;
            self.0
                .get(off..off + n)
                .map(<[u8]>::to_vec)
                .ok_or("short".into())
        }
    }

    /// The extents of a file of a real ext4 image are those ext4map.py
    /// finds, read through a stand-in for stock's SSH.
    #[test]
    fn the_extents_are_ext4maps() {
        if !(tool("mkfs.ext4") && tool("debugfs") && tool("python3")) {
            return;
        }
        let t = TestDir::new();
        let root = t.path().join("root");
        fs::create_dir_all(&root).unwrap();
        // Big enough for an extent tree past the inode's four extents is not
        // needed: a few MiB, written as the build writes its payloads.
        let body: Vec<u8> = (0..3_500_000u32).map(|n| (n % 251) as u8).collect();
        fs::write(root.join("u6e.initrd"), &body).unwrap();
        fs::write(root.join("small"), b"x").unwrap();
        let img = t.path().join("p5.img");
        let mkfs = Std::new("mkfs.ext4")
            .args(["-q", "-F", "-b", "4096", "-d"])
            .arg(&root)
            .arg(&img)
            .arg("16M")
            .output()
            .unwrap();
        assert!(mkfs.status.success(), "{mkfs:?}");
        let stat = Std::new("debugfs")
            .args(["-R", "stat /u6e.initrd"])
            .arg(&img)
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&stat.stdout);
        let ino: u64 = stat
            .split_whitespace()
            .skip_while(|w| *w != "Inode:")
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        // The stand-in: the partition is the image, starting at sector 2048.
        let ssh = t.path().join("ssh");
        fs::write(
            &ssh,
            format!(
                "#!/bin/sh\ncase \"$1\" in *start) echo 2048 ;; \
                 *) sh -c \"$(echo \"$1\" | sed 's#{PARTITION}#{}#')\" ;; esac\n",
                img.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&ssh, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../boot/ext4map.py");
        let py = Std::new("python3")
            .arg("-I")
            .arg(script)
            .arg(ino.to_string())
            .arg(&ssh)
            .output()
            .unwrap();
        assert!(py.status.success(), "{py:?}");
        let theirs: Vec<Extent> = String::from_utf8_lossy(&py.stdout)
            .lines()
            .filter(|l| l.starts_with("EXT"))
            .map(|l| {
                let field = |k: &str| {
                    l.split_whitespace()
                        .find_map(|w| w.strip_prefix(k)?.parse().ok())
                        .unwrap()
                };
                Extent {
                    disk_sector: field("disk_sector="),
                    sectors: field("sectors="),
                }
            })
            .collect();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut disk = Image(fs::read(&img).unwrap());
        let ours = rt.block_on(map(&mut disk, 2048, ino)).unwrap();
        assert!(!ours.is_empty());
        assert_eq!(ours, theirs);
        let sectors: u64 = ours.iter().map(|e| e.sectors).sum();
        assert_eq!(sectors * 512, (body.len() as u64).div_ceil(4096) * 4096);
        // What is not a file system's inode.
        assert!(rt.block_on(map(&mut Image(vec![0; 4096]), 0, ino)).is_err());
    }

    /// A stand-in for an AP's two systems over SSH, in `dir`: `state` says
    /// which runs (`debian`, `stock`, or anything else for neither), the
    /// other refuses the login; stock's payload directory, its RAM file and
    /// its partition (an ext4 image whose file `ino` every `ls -i` names)
    /// are files of `dir`. Every call is logged to `calls`.
    fn fake_ap(dir: &Path, ino: u64) -> (PathBuf, PathBuf) {
        let ssh = dir.join("ssh");
        let d = dir.display();
        let script = format!(
            r#"#!/bin/bash
sys=${{FAKE_SYSTEM:-image}}
while [ "$1" != -- ]; do shift; done; shift
cmd=$2
echo "$sys $1 $cmd" >> {d}/calls
want=debian; [ "$sys" = stock ] && want=stock
[ "$(cat {d}/state)" = "$want" ] || exit 255
case $cmd in
true) exit 0 ;;
'/usr/local/sbin/u6e-arm disarm && systemctl reboot') echo stock > {d}/state; exit 255 ;;
reboot) echo debian > {d}/state; exit 255 ;;
'fw_setenv -s -') cat > {d}/env; exit 0 ;;
'fw_printenv bootcmd_real') sed -n 's/^bootcmd_real /bootcmd_real=/p' {d}/env; exit 0 ;;
'cat /sys/block/mmcblk0/mmcblk0p5/start') echo 2048; exit 0 ;;
'ls -i '*) echo "{ino} ${{cmd#ls -i }}"; exit 0 ;;
esac
cmd=${{cmd//\/tmp\/log\/.u6e/{d}/stage}}
cmd=${{cmd//\/tmp\/u6e-chunk/{d}/chunk}}
cmd=${{cmd//\/dev\/mmcblk0p5/{d}/p5.img}}
exec sh -c "$cmd"
"#
        );
        fs::write(&ssh, script).unwrap();
        let sshpass = dir.join("sshpass");
        fs::write(
            &sshpass,
            "#!/bin/bash\nshift 2\nexec env FAKE_SYSTEM=stock \"$@\"\n",
        )
        .unwrap();
        for p in [&ssh, &sshpass] {
            fs::set_permissions(p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        }
        (ssh, sshpass)
    }

    /// The staging's steps against the stand-in: from the image into stock,
    /// each payload written (only the chunks that differ, the second time)
    /// and checked, the boot armed, and back into the image; an AP that
    /// answers neither system is left untouched.
    #[test]
    fn a_staging_takes_the_ap_through_stock_and_back() {
        if !(tool("mkfs.ext4") && tool("debugfs")) {
            return;
        }
        let t = TestDir::new();
        let root = t.path().join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("u6e.initrd"), vec![7u8; 200_000]).unwrap();
        let img = t.path().join("p5.img");
        let mkfs = Std::new("mkfs.ext4")
            .args(["-q", "-F", "-b", "4096", "-d"])
            .arg(&root)
            .arg(&img)
            .arg("8M")
            .output()
            .unwrap();
        assert!(mkfs.status.success(), "{mkfs:?}");
        let stat = Std::new("debugfs")
            .args(["-R", "stat /u6e.initrd"])
            .arg(&img)
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&stat.stdout);
        let ino: u64 = stat
            .split_whitespace()
            .skip_while(|w| *w != "Inode:")
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let ap = t.path().join("ap");
        fs::create_dir_all(ap.join("stage")).unwrap();
        fs::copy(&img, ap.join("p5.img")).unwrap();
        fs::write(ap.join("state"), "debian\n").unwrap();
        let (ssh, sshpass) = fake_ap(&ap, ino);
        let image = t.path().join("img-1-ap1");
        fs::create_dir_all(&image).unwrap();
        let sizes = [208, 27_193, 300_000, 200_000];
        for ((_, file, _), size) in STAGED.iter().zip(sizes) {
            let body: Vec<u8> = (0..size).map(|n| (n % 253) as u8).collect();
            fs::write(image.join(file), body).unwrap();
        }
        let kept = Kept {
            id: "img-1-ap1".into(),
            dir: image.clone(),
            files: Vec::new(),
        };
        let waits = Waits {
            settle: Duration::ZERO,
            stock: Duration::from_secs(5),
            image: Duration::from_secs(5),
            poll: Duration::from_millis(50),
        };
        let creds = Credentials {
            root_key: t.path().join("key"),
            stock_user: "ubnt".into(),
            stock_password: t.path().join("pw"),
            known_hosts: t.path().join("hosts"),
        };
        let stager = Ssh {
            ssh,
            sshpass,
            ..Ssh::new(creds, waits)
        };
        let target = Target {
            ap: "ap1".into(),
            hostname: "u6e-ap1".into(),
            address: "192.0.2.16".into(),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let lines = std::sync::Mutex::new(Vec::new());
        let log = |l: String| lines.lock().unwrap().push(l);
        assert_eq!(
            rt.block_on(stager.stage(&target, &kept, &log)),
            Staged::Done
        );
        let read = |p: &str| fs::read_to_string(ap.join(p)).unwrap();
        assert_eq!(read("state"), "debian\n");
        for (name, file, _) in STAGED {
            let staged = fs::read(ap.join("stage").join(name)).unwrap();
            assert_eq!(staged, pad(fs::read(image.join(file)).unwrap()), "{name}");
        }
        assert!(read("env").contains("\nbootcmd_real setenv bootcmd_real bootubnt; saveenv;"));
        let seen = lines.lock().unwrap().clone();
        assert_eq!(seen[0], "ap1: disarmed, rebooting into stock");
        assert!(seen[1].starts_with("ap1: in stock after "), "{seen:?}");
        assert_eq!(seen[2], "u6e.zimg: 64 of 64 KiB written, 1 extent(s)");
        assert_eq!(seen[4], "u6e.initrd: 320 of 320 KiB written, 1 extent(s)");
        assert!(
            seen[6].starts_with("ap1: armed bootcmd_real=setenv"),
            "{seen:?}"
        );
        assert_eq!(seen[7], "ap1: rebooting into img-1-ap1");
        assert!(seen[8].starts_with("ap1: in its image after "), "{seen:?}");
        // Each host key checked under its own name.
        let calls = read("calls");
        assert!(calls.contains("image root@192.0.2.16 true"), "{calls}");
        assert!(
            calls.contains("stock ubnt@192.0.2.16 mkdir -p /tmp/log/.u6e"),
            "{calls}"
        );

        // Again, one chunk of the initrd changed: only that one is written.
        let mut initrd = fs::read(image.join("u6e.initrd")).unwrap();
        initrd[70_000] ^= 1;
        fs::write(image.join("u6e.initrd"), &initrd).unwrap();
        lines.lock().unwrap().clear();
        assert_eq!(
            rt.block_on(stager.stage(&target, &kept, &log)),
            Staged::Done
        );
        let seen = lines.lock().unwrap().clone();
        assert_eq!(seen[2], "u6e.zimg: 0 of 64 KiB written, 1 extent(s)");
        assert_eq!(seen[4], "u6e.initrd: 64 of 320 KiB written, 1 extent(s)");
        assert_eq!(fs::read(ap.join("stage/u6e.initrd")).unwrap(), pad(initrd));

        // Neither system answers: nothing is done.
        fs::write(ap.join("state"), "down\n").unwrap();
        assert!(matches!(
            rt.block_on(stager.stage(&target, &kept, &log)),
            Staged::Untouched(_)
        ));
    }
}

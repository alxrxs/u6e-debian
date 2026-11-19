//! One capture, from the agent's request to its end. The request is
//! checked, the helper's one capture slot taken (its lock), the packet
//! sockets opened with their programs before the client's flows are taken
//! (nothing between is missed), and the flows taken (`offload`). Then the
//! packets become pcapng, cut into chunks of at most
//! [`u6e_proto::msg::CHUNK_MAX`] sent at least every second, the agent
//! reading them as the controller acknowledges them: at most two chunks
//! wait here, and packets past them are dropped and counted rather than
//! held. The Wi-Fi ports are looked at again every two seconds, so a
//! client's new per-VLAN netdev is read within that, and, off the offload,
//! its frames marked there too.
//!
//! It ends at its deadline, at its size limit (no block is written past
//! it), when the agent shuts its side down (the last chunks and the state
//! still go), when the agent goes, or on a signal. The flows are given back
//! first, then the rest is sent. One thread, one `poll`.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use u6e_proto::frame::{read_frame, write_frame};
use u6e_proto::mac;
use u6e_proto::msg::{
    AgentMsg, CHUNK_MAX, CaptureChunk, CaptureFilter, CaptureMechanism, CaptureRequest,
    CaptureState, FilterProto,
};
use u6e_proto::netdev::wifi_port;

use crate::filter;
use crate::offload::{self, Devs, MIRROR, Paths};
use crate::pcapng::{self, Direction, ETHERNET, RAW};
use crate::sock::PacketSocket;

/// A chunk is sent once the next block would take it past this; one block
/// (a packet of the longest snaplen) fits [`CHUNK_MAX`] whatever.
const CHUNK_TARGET: usize = 64 << 10;
/// What waits for the agent at most: two chunks' frames.
const OUT_MAX: usize = 2 * (CHUNK_MAX + 64);
const FLUSH_EVERY: Duration = Duration::from_secs(1);
const RESCAN_EVERY: Duration = Duration::from_secs(2);
/// How long the agent may take to send its request, and to take the last
/// frames once the capture ended.
const AGENT_WAIT: Duration = Duration::from_secs(5);
/// Packets read from a socket per wake: the agent's side is served between.
const READS_MAX: usize = 256;

pub struct Config {
    pub paths: Paths,
    /// The AP's name, for the file's header.
    pub host: String,
    /// The AP's Wi-Fi ports and the mirror netdev, by name and index (the
    /// current network namespace's, as `if_nameindex` lists them).
    pub netdevs: fn() -> Vec<(String, u32)>,
}

/// The helper's lock: one capture at a time.
pub const LOCK: &str = "/run/u6e-capture/lock";

/// The lock, if no other capture holds it.
pub fn try_lock(paths: &Paths) -> io::Result<Option<File>> {
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(paths.at(LOCK))?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = io::Error::last_os_error();
        return match e.kind() {
            ErrorKind::WouldBlock => Ok(None),
            _ => Err(e),
        };
    }
    Ok(Some(f))
}

/// The netdevs of this network namespace.
pub fn netdevs() -> Vec<(String, u32)> {
    let mut out = Vec::new();
    // SAFETY: if_nameindex returns an array ended by a zero index, freed
    // below; each name is a NUL-terminated string within it.
    unsafe {
        let list = libc::if_nameindex();
        if list.is_null() {
            return out;
        }
        let mut i = list;
        while (*i).if_index != 0 {
            let name = std::ffi::CStr::from_ptr((*i).if_name);
            out.push((name.to_string_lossy().into_owned(), (*i).if_index));
            i = i.add(1);
        }
        libc::if_freenameindex(list);
    }
    out
}

fn state(
    id: u64,
    running: bool,
    mechanism: Option<CaptureMechanism>,
    reason: impl Into<String>,
) -> AgentMsg {
    AgentMsg::Capture(CaptureState {
        id,
        running,
        mechanism,
        bytes: 0,
        packets: 0,
        dropped: 0,
        reason: reason.into(),
    })
}

/// The filter as the file's header names it.
fn describe(f: &CaptureFilter) -> String {
    let mut parts = Vec::new();
    if let Some(p) = f.proto {
        parts.push(match p {
            FilterProto::Tcp => "tcp".to_owned(),
            FilterProto::Udp => "udp".into(),
            FilterProto::Icmp => "icmp".into(),
            FilterProto::Arp => "arp".into(),
        });
    }
    if let Some(p) = f.port {
        parts.push(format!("port {p}"));
    }
    if let Some(h) = f.host {
        parts.push(format!("host {h}"));
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(" ")
    }
}

/// Serves the capture `conn` asks for; `stop` (a signalfd) ends it early.
pub fn run(cfg: &Config, mut conn: UnixStream, stop: RawFd) -> io::Result<()> {
    conn.set_read_timeout(Some(AGENT_WAIT))?;
    let req: CaptureRequest = read_frame(&mut conn)?;
    let refuse = |conn: &mut UnixStream, why: String| {
        eprintln!("u6e-capture: {} refused: {why}", mac::format(req.mac));
        write_frame(conn, &state(req.id, false, None, format!("refused: {why}")))
    };
    if let Err(why) = req.check() {
        return refuse(&mut conn, why.into());
    }
    let Some(_lock) = try_lock(&cfg.paths)? else {
        return refuse(&mut conn, "another capture runs on this AP".into());
    };
    if let Err(why) = offload::restore_from(&cfg.paths) {
        return refuse(
            &mut conn,
            format!("an earlier capture's offload is not back: {why}"),
        );
    }
    let devs = (cfg.netdevs)();
    let mirror_dev = devs.iter().find(|(n, _)| n == MIRROR).map(|(_, i)| *i);
    let how = offload::mechanism(&cfg.paths, mirror_dev.is_some());
    let mut c = match Capture::open(cfg, &req, how, mirror_dev, conn.try_clone()?) {
        Ok(c) => c,
        Err(e) => return refuse(&mut conn, format!("no packet socket: {e}")),
    };
    let devs = Devs::of(devs.iter().map(|(n, _)| n.as_str()));
    if let Err(why) = offload::take(&cfg.paths, how, req.mac, req.snaplen, &devs) {
        return refuse(&mut conn, why);
    }
    c.marked = devs;
    eprintln!(
        "u6e-capture: {} for {} s, at most {} B, {} B a packet, filter {}, {} KiB of socket: {}",
        mac::format(req.mac),
        req.secs,
        req.max_bytes,
        req.snaplen,
        describe(&req.filter),
        c.ports.rcvbuf() >> 10,
        how_said(how)
    );
    let reason = c.serve(stop);
    let restored = offload::restore_from(&cfg.paths);
    if let Err(e) = &restored {
        eprintln!("u6e-capture: the offload is not back: {e}");
    }
    let reason = match restored {
        Ok(_) => reason,
        Err(e) => format!("{reason}; the offload is not back: {e}"),
    };
    let end = c.state(false, &reason);
    eprintln!(
        "u6e-capture: {}: {reason}; {} B, {} packets, {} dropped",
        mac::format(req.mac),
        end.bytes,
        end.packets,
        end.dropped
    );
    c.finish(reason)
}

fn how_said(how: CaptureMechanism) -> &'static str {
    match how {
        CaptureMechanism::Mirror => "its flows stay offloaded and the NSS mirrors them",
        CaptureMechanism::OffOffload => {
            "its flows, and no other client's, are taken off the offload"
        }
    }
}

struct Capture {
    req: CaptureRequest,
    how: CaptureMechanism,
    paths: Paths,
    /// Off the offload, the netdevs the client's frames are marked on.
    marked: Devs,
    conn: UnixStream,
    ports: PacketSocket,
    mirror: Option<PacketSocket>,
    /// The Wi-Fi ports by index, as last looked at.
    names: BTreeMap<u32, String>,
    netdevs: fn() -> Vec<(String, u32)>,
    /// Each interface's description, by index and link type.
    ids: Vec<(u32, u16)>,
    chunk: Vec<u8>,
    out: Vec<u8>,
    seq: u64,
    bytes: u64,
    packets: u64,
    drops: u64,
    started: Instant,
}

/// Why the capture ends.
enum End {
    Size,
}

impl Capture {
    fn open(
        cfg: &Config,
        req: &CaptureRequest,
        how: CaptureMechanism,
        mirror_dev: Option<u32>,
        conn: UnixStream,
    ) -> io::Result<Self> {
        let ports = PacketSocket::open(None)?;
        let mirror = match (how, mirror_dev) {
            (CaptureMechanism::Mirror, Some(i)) => {
                let s = PacketSocket::open(Some(i as i32))?;
                s.filter(&filter::mirror(req.mac, &req.filter, req.snaplen))?;
                Some(s)
            }
            _ => None,
        };
        let mut c = Capture {
            req: req.clone(),
            how,
            paths: cfg.paths.clone(),
            marked: Devs::default(),
            conn,
            ports,
            mirror,
            names: BTreeMap::new(),
            netdevs: cfg.netdevs,
            ids: Vec::new(),
            chunk: Vec::new(),
            out: Vec::new(),
            seq: 0,
            bytes: 0,
            packets: 0,
            drops: 0,
            started: Instant::now(),
        };
        c.rescan()?;
        let comment = format!(
            "{}: client {}, {} s at most, filter {}; {}",
            cfg.host,
            mac::format(req.mac),
            req.secs,
            describe(&req.filter),
            how_said(how)
        );
        c.chunk = pcapng::section(&comment);
        c.bytes = c.chunk.len() as u64;
        Ok(c)
    }

    /// Looks at the netdevs again: a change of the Wi-Fi ports gets the
    /// program again and, off the offload, of the ports or the VLANs' the
    /// client's marks.
    fn rescan(&mut self) -> io::Result<()> {
        let all = (self.netdevs)();
        if self.how == CaptureMechanism::OffOffload && !self.marked.ports.is_empty() {
            let devs = Devs::of(all.iter().map(|(n, _)| n.as_str()));
            if devs != self.marked && !devs.ports.is_empty() {
                offload::follow(&self.paths, self.req.mac, &devs).map_err(io::Error::other)?;
                self.marked = devs;
            }
        }
        let now: BTreeMap<u32, String> = all
            .into_iter()
            .filter(|(n, _)| wifi_port(n))
            .map(|(n, i)| (i, n))
            .collect();
        if now != self.names {
            let idx: Vec<u32> = now.keys().copied().collect();
            let prog = filter::ports(&idx, self.req.mac, &self.req.filter, self.req.snaplen)
                .map_err(io::Error::other)?;
            self.ports.filter(&prog)?;
            self.names = now;
        }
        Ok(())
    }

    /// Runs until the capture ends; why it ended.
    fn serve(&mut self, stop: RawFd) -> String {
        if let Err(e) = self.send_now(&AgentMsg::Capture(self.state(true, "started"))) {
            return format!("the agent went: {e}");
        }
        let _ = self.conn.set_nonblocking(true);
        let deadline = self.started + Duration::from_secs(u64::from(self.req.secs));
        let (mut flushed, mut scanned) = (Instant::now(), Instant::now());
        let mut buf = vec![0u8; usize::from(self.req.snaplen)];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return "its time is up".into();
            }
            if now >= scanned + RESCAN_EVERY {
                scanned = now;
                if let Err(e) = self.rescan() {
                    return format!("the ports could not be followed: {e}");
                }
            }
            if now >= flushed + FLUSH_EVERY {
                flushed = now;
                self.flush_chunk();
            }
            let wake = deadline
                .min(flushed + FLUSH_EVERY)
                .min(scanned + RESCAN_EVERY);
            let ms = wake.saturating_duration_since(now).as_millis().min(1000) as i32;
            let out = if self.out.is_empty() {
                0
            } else {
                libc::POLLOUT
            };
            let mut fds = vec![
                pollfd(stop, libc::POLLIN),
                pollfd(self.conn.as_raw_fd(), libc::POLLIN | out),
                pollfd(self.ports.fd(), libc::POLLIN),
            ];
            if let Some(m) = &self.mirror {
                fds.push(pollfd(m.fd(), libc::POLLIN));
            }
            // SAFETY: `fds` is a valid array of pollfds for the call.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return format!("poll: {e}");
            }
            if fds[0].revents != 0 {
                return "the helper was stopped".into();
            }
            if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return "the agent went".into();
            }
            if fds[1].revents & libc::POLLIN != 0 {
                let mut b = [0u8; 16];
                match self.conn.read(&mut b) {
                    Ok(0) => return "stopped".into(),
                    Ok(_) => return "the agent sent more than its request".into(),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) => return format!("the agent went: {e}"),
                }
            }
            if let Err(e) = self.write_out() {
                return format!("the agent went: {e}");
            }
            if let Err(End::Size) = self
                .read_ports(&mut buf)
                .and_then(|()| self.read_mirror(&mut buf))
            {
                return "its size limit is reached".into();
            }
        }
    }

    fn read_ports(&mut self, buf: &mut [u8]) -> Result<(), End> {
        for _ in 0..READS_MAX {
            let Ok(Some(r)) = self.ports.recv(buf) else {
                return Ok(());
            };
            let Some(name) = self.names.get(&(r.ifindex as u32)).cloned() else {
                continue;
            };
            let dir = if r.outgoing {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            self.add(
                r.ifindex as u32,
                &name,
                ETHERNET,
                r.ts_ns,
                &buf[..r.len],
                r.orig_len,
                Some(dir),
            )?;
        }
        Ok(())
    }

    fn read_mirror(&mut self, buf: &mut [u8]) -> Result<(), End> {
        for _ in 0..READS_MAX {
            let Some(Ok(Some(r))) = self.mirror.as_ref().map(|m| m.recv(buf)) else {
                return Ok(());
            };
            let data = &buf[..r.len];
            let (link, dir) = if filter::is_frame(data, self.req.mac) {
                let to_client = data[..6] == self.req.mac;
                let d = if to_client {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                };
                (ETHERNET, Some(d))
            } else {
                (RAW, None)
            };
            let data = data.to_vec();
            self.add(
                r.ifindex as u32,
                MIRROR,
                link,
                r.ts_ns,
                &data,
                r.orig_len,
                dir,
            )?;
        }
        Ok(())
    }

    /// Writes a packet, and its interface's description the first time;
    /// a packet there is no room for waits for nothing: it is dropped.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        ifindex: u32,
        name: &str,
        link: u16,
        ts_ns: u64,
        data: &[u8],
        orig_len: u32,
        dir: Option<Direction>,
    ) -> Result<(), End> {
        let known = self.ids.iter().position(|k| *k == (ifindex, link));
        let id = known.unwrap_or(self.ids.len()) as u32;
        let mut block = Vec::new();
        if known.is_none() {
            block = pcapng::interface(name, link, u32::from(self.req.snaplen));
        }
        block.extend(pcapng::packet(id, ts_ns, data, orig_len, dir));
        if self.bytes + block.len() as u64 > u64::from(self.req.max_bytes) {
            return Err(End::Size);
        }
        if self.chunk.len() + block.len() > CHUNK_TARGET {
            // The agent takes what it can first; an error is the loop's to see.
            let _ = self.write_out();
            if !self.flush_chunk() {
                self.drops += 1;
                return Ok(());
            }
        }
        if known.is_none() {
            self.ids.push((ifindex, link));
        }
        self.bytes += block.len() as u64;
        self.chunk.extend(block);
        self.packets += 1;
        Ok(())
    }

    /// Moves the chunk to what waits for the agent, if there is room; false
    /// when there is not.
    fn flush_chunk(&mut self) -> bool {
        if self.chunk.is_empty() {
            return true;
        }
        let msg = AgentMsg::CaptureChunk(CaptureChunk {
            id: self.req.id,
            seq: self.seq,
            data: std::mem::take(&mut self.chunk),
        });
        let mut frame = Vec::new();
        write_frame(&mut frame, &msg).expect("a chunk fits a frame");
        if self.out.len() + frame.len() > OUT_MAX {
            let AgentMsg::CaptureChunk(c) = msg else {
                unreachable!()
            };
            self.chunk = c.data;
            return false;
        }
        self.out.extend(frame);
        self.seq += 1;
        true
    }

    /// Writes what the agent can take now.
    fn write_out(&mut self) -> io::Result<()> {
        while !self.out.is_empty() {
            match self.conn.write(&self.out) {
                Ok(n) => {
                    self.out.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn state(&self, running: bool, reason: &str) -> CaptureState {
        CaptureState {
            id: self.req.id,
            running,
            mechanism: Some(self.how),
            bytes: self.bytes,
            packets: self.packets,
            dropped: self.drops
                + self.ports.drops()
                + self.mirror.as_ref().map_or(0, |m| m.drops()),
            reason: reason.into(),
        }
    }

    fn send_now(&mut self, msg: &AgentMsg) -> io::Result<()> {
        write_frame(&mut self.conn, msg)
    }

    /// Sends what is left and the final state, waiting a little for the
    /// agent to take them.
    fn finish(mut self, reason: String) -> io::Result<()> {
        self.conn.set_nonblocking(false)?;
        self.conn.set_write_timeout(Some(AGENT_WAIT))?;
        self.flush_chunk();
        let mut last = std::mem::take(&mut self.out);
        if !self.chunk.is_empty() {
            let msg = AgentMsg::CaptureChunk(CaptureChunk {
                id: self.req.id,
                seq: self.seq,
                data: std::mem::take(&mut self.chunk),
            });
            write_frame(&mut last, &msg)?;
        }
        write_frame(&mut last, &AgentMsg::Capture(self.state(false, &reason)))?;
        self.conn.write_all(&last)
    }
}

fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

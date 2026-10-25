//! The spectrum analyzer's fan-out. A radio scans only while someone watches
//! it: the first watcher of `<ap>/<radio>` has the controller send the AP
//! `SpectrumStart`, and `SpectrumStop` goes [`Limits::linger`] after the last
//! one leaves (so a reload or a glance at another radio keeps the scan), or
//! [`Limits::limit`] after the start, watched or not; a watcher restarts it by
//! asking again. However many watch a radio it scans once: each frame is
//! encoded once and broadcast to the sockets of its watchers.
//!
//! A frame goes to the browser as one binary WebSocket message, little-endian:
//!
//! | offset  | size | field                                   |
//! |---------|------|-----------------------------------------|
//! | 0       | 1    | layout, [`LAYOUT`]                      |
//! | 1       | 1    | noise floor, dBm (i8)                   |
//! | 2       | 2    | centre of the channel, MHz              |
//! | 4       | 2    | width of the channel, MHz               |
//! | 6       | 2    | n, the number of bins                   |
//! | 8       | 4    | frequency of the first bin, 0.1 MHz     |
//! | 12      | 4    | step from one bin to the next, kHz      |
//! | 16      | 8    | when the AP took it, Unix ms            |
//! | 24      | 1    | k, the length of the key                |
//! | 25      | k    | the key, `<ap>/<radio>`, UTF-8          |
//! | 25 + k  | n    | the bins, dBm (i8) each                 |

use std::time::{Duration, Instant, SystemTime};

use axum::body::Bytes;
use tokio::sync::broadcast;
use u6e_proto::msg::{CtlMsg, SpectrumFrame};

use crate::state::{Change, Shared, State};

/// The radios that scan, by the names the image gives them; nothing else is
/// ever asked of an AP.
pub const RADIOS: [&str; 3] = ["radio24", "radio5", "radio6"];
/// The version of the binary layout above.
pub const LAYOUT: u8 = 1;
/// Frames queued per watcher; one further behind skips to the newest.
const FRAMES_QUEUED: usize = 16;

/// How long a scan outlives its last watcher, and the longest it runs.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub linger: Duration,
    pub limit: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            linger: Duration::from_secs(5),
            limit: Duration::from_secs(600),
        }
    }
}

/// Why a scan stopped, as the UI words it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// Its last watcher left.
    Idle,
    /// It ran for [`Limits::limit`].
    Limit,
    /// The AP's link went down, and the agent stops a scan with it.
    Link,
    /// The AP stopped it, for the reason it gave.
    Ap,
}

impl Stopped {
    pub fn as_str(self) -> &'static str {
        match self {
            Stopped::Idle => "idle",
            Stopped::Limit => "limit",
            Stopped::Link => "link",
            Stopped::Ap => "ap",
        }
    }
}

/// One radio's scan.
pub struct Scan {
    watchers: usize,
    /// When the AP was asked to scan, while it is.
    asked: Option<(Instant, SystemTime)>,
    /// When the last watcher left, while none watches.
    left: Option<Instant>,
    /// What the AP last said: whether it scans, and why not.
    pub running: bool,
    pub detail: String,
    /// Why it stopped, once it has.
    pub stopped: Option<Stopped>,
    /// Frames received since the controller started.
    pub frames_total: u64,
    frames: broadcast::Sender<Bytes>,
}

impl Scan {
    pub fn new() -> Self {
        Scan {
            watchers: 0,
            asked: None,
            left: None,
            running: false,
            detail: String::new(),
            stopped: None,
            frames_total: 0,
            frames: broadcast::Sender::new(FRAMES_QUEUED),
        }
    }

    pub fn watchers(&self) -> usize {
        self.watchers
    }

    /// Since when the AP is asked to scan, while it is.
    pub fn since(&self) -> Option<SystemTime> {
        self.asked.map(|(_, at)| at)
    }

    /// Takes the AP's word on it; a scan the AP stopped while asked to
    /// scan stopped for the AP's reason.
    pub fn report(&mut self, running: bool, detail: String) {
        if !running && self.asked.take().is_some() {
            self.stopped = Some(Stopped::Ap);
        }
        self.running = running;
        self.detail = detail;
    }

    /// No longer asked to scan, for `why`; false if it was not.
    pub fn end(&mut self, why: Stopped) -> bool {
        if self.asked.take().is_none() {
            return false;
        }
        self.stopped = Some(why);
        true
    }

    /// Passes `f`, of `key`, to the watchers.
    pub fn frame(&mut self, key: &str, f: &SpectrumFrame) {
        self.frames_total += 1;
        if self.frames.receiver_count() > 0 {
            let _ = self.frames.send(Bytes::from(encode(key, f)));
        }
    }

    /// Why the scan is to stop at `now`, or else when to look again.
    fn due(&self, now: Instant, limits: Limits) -> Result<Option<Instant>, Stopped> {
        let Some((since, _)) = self.asked else {
            return Ok(None);
        };
        let idle = self.left.map(|at| at + limits.linger);
        let ends = since + limits.limit;
        if idle.is_some_and(|t| t <= now) {
            return Err(Stopped::Idle);
        }
        if ends <= now {
            return Err(Stopped::Limit);
        }
        Ok(Some(idle.map_or(ends, |t| t.min(ends))))
    }
}

impl Default for Scan {
    fn default() -> Self {
        Scan::new()
    }
}

/// `<ap>/<radio>` as the UI names a radio, when the radio is one that scans.
pub fn parse(key: &str) -> Option<(&str, &str)> {
    let (ap, radio) = key.split_once('/')?;
    RADIOS.contains(&radio).then_some((ap, radio))
}

/// One frame of `key` in the layout of the module's table. A key or a frame
/// too long for its length field is cut short: neither ever is, the key being
/// a configured AP and a radio, a frame at most 600 B.
pub fn encode(key: &str, f: &SpectrumFrame) -> Vec<u8> {
    let key = &key.as_bytes()[..key.len().min(usize::from(u8::MAX))];
    let bins = &f.bins[..f.bins.len().min(usize::from(u16::MAX))];
    let mut out = Vec::with_capacity(25 + key.len() + bins.len());
    out.push(LAYOUT);
    out.extend(f.noise_dbm.to_le_bytes());
    out.extend(f.center_mhz.to_le_bytes());
    out.extend(f.width_mhz.to_le_bytes());
    out.extend((bins.len() as u16).to_le_bytes());
    out.extend(f.first_mhz_x10.to_le_bytes());
    out.extend(f.step_khz.to_le_bytes());
    out.extend(f.at_ms.to_le_bytes());
    out.push(key.len() as u8);
    out.extend_from_slice(key);
    out.extend(bins.iter().map(|b| b.to_le_bytes()[0]));
    out
}

impl State {
    /// One more watcher of the scan of `radio` on `ap`, which starts it if
    /// it is not running; its frames, or why there are none.
    pub fn watch_spectrum(
        &mut self,
        ap: &str,
        radio: &str,
        now: Instant,
    ) -> Result<broadcast::Receiver<Bytes>, &'static str> {
        if !RADIOS.contains(&radio) {
            return Err("not a radio that scans");
        }
        let entry = self.aps.get_mut(ap).ok_or("not a configured AP")?;
        let live = entry.session.as_ref().ok_or("the AP is not connected")?;
        let scan = entry.scans.entry(radio.to_owned()).or_default();
        let start = scan.asked.is_none();
        if start {
            let radio = radio.to_owned();
            live.outbox
                .try_send(CtlMsg::SpectrumStart { radio })
                .map_err(|_| "the AP is not keeping up")?;
            scan.asked = Some((now, SystemTime::now()));
            scan.stopped = None;
        }
        scan.watchers += 1;
        scan.left = None;
        let frames = scan.frames.subscribe();
        if start {
            // The limit counts from here.
            self.wake.notify_one();
        }
        // The other watchers see one more.
        self.notify(Change::Spectrum(ap.to_owned(), radio.to_owned()));
        Ok(frames)
    }

    /// One watcher fewer, who left at `at`.
    fn unwatch_spectrum(&mut self, ap: &str, radio: &str, at: Instant) {
        let Some(scan) = self.aps.get_mut(ap).and_then(|a| a.scans.get_mut(radio)) else {
            return;
        };
        scan.watchers -= 1;
        if scan.watchers == 0 {
            scan.left = Some(at);
            self.wake.notify_one();
        }
        self.notify(Change::Spectrum(ap.to_owned(), radio.to_owned()));
    }

    /// Stops the scans due to stop at `now`; when the next one is due.
    pub fn stop_scans_due(&mut self, now: Instant) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut stopped = Vec::new();
        for (name, ap) in &mut self.aps {
            for (radio, scan) in &mut ap.scans {
                match scan.due(now, self.spectrum) {
                    Ok(None) => {}
                    Ok(Some(at)) => next = Some(next.map_or(at, |n| n.min(at))),
                    Err(why) => {
                        // A session too far behind to take this is dropped
                        // soon, and the agent stops its scans with the link.
                        if let Some(live) = &ap.session {
                            let radio = radio.clone();
                            let _ = live.outbox.try_send(CtlMsg::SpectrumStop { radio });
                        }
                        scan.end(why);
                        stopped.push(Change::Spectrum(name.clone(), radio.clone()));
                    }
                }
            }
        }
        for c in stopped {
            self.notify(c);
        }
        next
    }
}

impl Shared {
    /// Watches the scan of `radio` on `ap` until the [`Watching`] is
    /// dropped; see [`State::watch_spectrum`].
    pub fn watch_spectrum(&self, ap: &str, radio: &str) -> Result<Watching, &'static str> {
        let frames = self.write().watch_spectrum(ap, radio, Instant::now())?;
        Ok(Watching {
            shared: self.clone(),
            ap: ap.to_owned(),
            radio: radio.to_owned(),
            frames,
            gone: None,
        })
    }
}

/// One watcher of a radio's scan, and the frames that come for it.
pub struct Watching {
    shared: Shared,
    pub ap: String,
    pub radio: String,
    pub frames: broadcast::Receiver<Bytes>,
    /// When the watcher was last heard of, if it left without a word.
    gone: Option<Instant>,
}

impl Watching {
    /// Ends the watch of one who was last heard of at `at`: the scan
    /// lingers from then, not from when the silence was noticed.
    pub fn gone_since(mut self, at: Instant) {
        self.gone = Some(at);
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        let at = self.gone.unwrap_or_else(Instant::now);
        self.shared
            .write()
            .unwatch_spectrum(&self.ap, &self.radio, at);
    }
}

/// Stops each scan when it is due, for the life of the process.
pub async fn supervise(state: Shared) {
    let wake = state.read().wake.clone();
    loop {
        let next = state.write().stop_scans_due(Instant::now());
        match next {
            Some(at) => {
                tokio::select! {
                    () = wake.notified() => {}
                    () = tokio::time::sleep_until(at.into()) => {}
                }
            }
            None => wake.notified().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(bins: Vec<i8>) -> SpectrumFrame {
        SpectrumFrame {
            radio: "radio5".into(),
            at_ms: 0x0102_0304_0506_0708,
            center_mhz: 5210,
            width_mhz: 80,
            first_mhz_x10: 51_700,
            step_khz: 312,
            bins,
            noise_dbm: -95,
        }
    }

    /// The frame `encode` wrote, read back as the UI reads it.
    fn decode(b: &[u8]) -> (String, SpectrumFrame) {
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        assert_eq!(b[0], LAYOUT);
        let n = usize::from(u16_at(6));
        let k = usize::from(b[24]);
        let key = String::from_utf8(b[25..25 + k].to_vec()).unwrap();
        assert_eq!(b.len(), 25 + k + n);
        let f = SpectrumFrame {
            radio: key.split_once('/').unwrap().1.into(),
            at_ms: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            center_mhz: u16_at(2),
            width_mhz: u16_at(4),
            first_mhz_x10: u32_at(8),
            step_khz: u32_at(12),
            bins: b[25 + k..].iter().map(|&x| x as i8).collect(),
            noise_dbm: b[1] as i8,
        };
        (key, f)
    }

    #[test]
    fn a_frame_round_trips_through_its_layout() {
        let f = frame((-128..=127).step_by(3).map(|v| v as i8).collect());
        let bytes = encode("ap1/radio5", &f);
        assert_eq!(decode(&bytes), ("ap1/radio5".into(), f));
        // The header pinned: a change to it is a change to the UI's reader.
        assert_eq!(
            bytes[..35],
            [
                1, 0xa1, 0x5a, 0x14, 80, 0, 86, 0, 0xf4, 0xc9, 0, 0, 0x38, 1, 0, 0, 8, 7, 6, 5, 4,
                3, 2, 1, 10, b'a', b'p', b'1', b'/', b'r', b'a', b'd', b'i', b'o', b'5'
            ]
        );
        assert_eq!(bytes[35..37], [0x80, 0x83]);
        let empty = encode("ap2/radio24", &frame(Vec::new()));
        assert!(decode(&empty).1.bins.is_empty());
    }

    #[test]
    fn only_the_scanning_radios_are_keys() {
        assert_eq!(parse("ap1/radio5"), Some(("ap1", "radio5")));
        assert_eq!(parse("ap1/radio24"), Some(("ap1", "radio24")));
        for bad in ["ap1/phy0", "ap1", "ap1/radio5/x", "ap1/../radio5", ""] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_scan_stops_after_its_linger_or_its_limit() {
        let limits = Limits {
            linger: Duration::from_secs(5),
            limit: Duration::from_secs(600),
        };
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        let mut scan = Scan::new();
        assert_eq!(scan.due(t0, limits), Ok(None));
        scan.asked = Some((t0, SystemTime::now()));
        scan.watchers = 1;
        assert_eq!(scan.due(at(1), limits), Ok(Some(at(600))));
        // The last watcher leaves at 100 s.
        scan.watchers = 0;
        scan.left = Some(at(100));
        assert_eq!(scan.due(at(104), limits), Ok(Some(at(105))));
        assert_eq!(scan.due(at(105), limits), Err(Stopped::Idle));
        // Watched all along, it still stops at the limit.
        scan.left = None;
        assert_eq!(scan.due(at(600), limits), Err(Stopped::Limit));
        // An AP that stops a scan it was asked for stopped it itself.
        scan.report(true, String::new());
        scan.report(false, "helper gone".into());
        assert_eq!((scan.stopped, scan.asked), (Some(Stopped::Ap), None));
        assert!(!scan.end(Stopped::Idle));
    }
}

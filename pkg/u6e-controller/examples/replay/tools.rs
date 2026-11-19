//! The replay's rate limits and captures, as an AP's agent and its helpers
//! would have them. A limit stands on the AP that has its client or its SSID
//! (download on the client's BSS, upload on the uplink), its classes'
//! bytes growing with the client's traffic, else it waits; a client limited
//! only for upload whose last byte is 03 reads as not enforced, as an NSS
//! that does not shape its traffic would make it. A capture streams a made-up
//! pcapng file of the client's frames, a chunk a second within the
//! controller's credit, until its time or size is up or it is stopped; `ap1`
//! takes the flows off the offload, `ap2` mirrors them.

use u6e_proto::msg::{
    AgentMsg, CaptureChunk, CaptureMechanism, CaptureRequest, CaptureState, Limit, LimitState,
    LimitStatus, LimitTarget, Snapshot,
};
use u6e_proto::text;

/// How each limit stands on the AP `snap` is of.
pub fn states(limits: &[Limit], snap: &Snapshot) -> Vec<LimitState> {
    limits
        .iter()
        .map(|l| {
            let (status, detail, bytes) = match &l.target {
                LimitTarget::Client(m) => match snap.stations.iter().find(|s| s.mac == *m) {
                    None => (LimitStatus::Waiting, "not on this AP".to_owned(), (0, 0)),
                    Some(_) if m[5] == 3 && l.rate.down_kbit.is_none() => (
                        LimitStatus::NotEnforced,
                        format!(
                            "its NSS class counted none of the {} it sent in a minute",
                            text::bytes(3 << 20)
                        ),
                        (0, 0),
                    ),
                    Some(s) => {
                        let bss = &snap.bsss[usize::from(s.bss)].ifname;
                        let detail = match (l.rate.down_kbit, l.rate.up_kbit) {
                            (Some(_), Some(_)) => format!("download on {bss}, upload on lan"),
                            (Some(_), None) => format!("download on {bss}"),
                            _ => "upload on lan".into(),
                        };
                        (
                            LimitStatus::Enforced,
                            detail,
                            (s.tx_bytes / 3, s.rx_bytes / 3),
                        )
                    }
                },
                LimitTarget::Ssid(ssid) => {
                    let vaps: Vec<&str> = snap
                        .bsss
                        .iter()
                        .filter(|b| b.ssid == *ssid)
                        .map(|b| b.ifname.as_str())
                        .collect();
                    if vaps.is_empty() {
                        (
                            LimitStatus::Waiting,
                            "no BSS of it on this AP".into(),
                            (0, 0),
                        )
                    } else {
                        let on = vaps.join(", ");
                        (
                            LimitStatus::Enforced,
                            format!("download on {on}"),
                            (1 << 24, 1 << 22),
                        )
                    }
                }
            };
            LimitState {
                target: l.target.clone(),
                status,
                detail,
                down_bytes: bytes.0,
                up_bytes: bytes.1,
            }
        })
        .collect()
}

/// A capture being made up.
pub struct Capture {
    pub request: CaptureRequest,
    started: u64,
    seq: u64,
    acked: Option<u64>,
    bytes: u64,
    packets: u64,
    mechanism: CaptureMechanism,
}

/// The chunks the controller may leave unacknowledged.
const CREDIT: u64 = 4;

impl Capture {
    pub fn start(ap: usize, request: CaptureRequest, now_s: u64) -> (Self, AgentMsg) {
        let mechanism = if ap == 0 {
            CaptureMechanism::OffOffload
        } else {
            CaptureMechanism::Mirror
        };
        let c = Capture {
            request,
            started: now_s,
            seq: 0,
            acked: None,
            bytes: 0,
            packets: 0,
            mechanism,
        };
        let state = c.state(true, "started");
        (c, state)
    }

    pub fn state(&self, running: bool, reason: &str) -> AgentMsg {
        AgentMsg::Capture(CaptureState {
            id: self.request.id,
            running,
            mechanism: Some(self.mechanism),
            bytes: self.bytes,
            packets: self.packets,
            dropped: 0,
            reason: reason.into(),
        })
    }

    pub fn ack(&mut self, seq: u64) {
        self.acked = Some(seq);
    }

    /// The next second's chunk, if the credit allows one; with the capture's
    /// end when its time or size is up.
    pub fn next(&mut self, now_s: u64) -> (Option<AgentMsg>, Option<AgentMsg>) {
        if now_s >= self.started + u64::from(self.request.secs) {
            return (None, Some(self.state(false, "its time is up")));
        }
        let unacked = self.seq - self.acked.map_or(0, |a| a + 1);
        if unacked >= CREDIT {
            return (None, None);
        }
        let mut data = if self.seq == 0 {
            header(&self.request)
        } else {
            Vec::new()
        };
        for i in 0..40 {
            data.extend(packet(&self.request, now_s, i));
        }
        if self.bytes + data.len() as u64 > u64::from(self.request.max_bytes) {
            return (None, Some(self.state(false, "its size limit is reached")));
        }
        self.bytes += data.len() as u64;
        self.packets += 40;
        let chunk = CaptureChunk {
            id: self.request.id,
            seq: self.seq,
            data,
        };
        self.seq += 1;
        (Some(AgentMsg::CaptureChunk(chunk)), None)
    }
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let len = (12 + body.len()) as u32;
    let mut b = kind.to_le_bytes().to_vec();
    b.extend(len.to_le_bytes());
    b.extend(body);
    b.extend(len.to_le_bytes());
    b
}

/// A section header and the one interface of the made-up file.
fn header(r: &CaptureRequest) -> Vec<u8> {
    let mut shb = 0x1A2B_3C4Du32.to_le_bytes().to_vec();
    shb.extend(1u16.to_le_bytes());
    shb.extend(0u16.to_le_bytes());
    shb.extend((-1i64).to_le_bytes());
    shb.extend(0u32.to_le_bytes());
    let mut idb = 1u16.to_le_bytes().to_vec();
    idb.extend(0u16.to_le_bytes());
    idb.extend(u32::from(r.snaplen).to_le_bytes());
    idb.extend(0u32.to_le_bytes());
    let mut out = block(0x0A0D_0D0A, &shb);
    out.extend(block(1, &idb));
    out
}

/// A made-up TCP frame of the client's, cut at the snaplen.
fn packet(r: &CaptureRequest, now_s: u64, i: u64) -> Vec<u8> {
    let mut frame = vec![0x02, 0, 0, 0, 0, 0xfe];
    frame.extend(r.mac);
    frame.extend([
        0x08, 0x00, 0x45, 0, 0x05, 0xdc, 0, 0, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 10, 198, 51, 100, 7,
    ]);
    frame.extend(443u16.to_be_bytes());
    frame.extend(51_000u16.to_be_bytes());
    frame.resize(1514, 0);
    let cut = frame.len().min(usize::from(r.snaplen));
    let ts = (now_s * 1_000_000) + i * 20_000;
    let mut epb = 0u32.to_le_bytes().to_vec();
    epb.extend(((ts >> 32) as u32).to_le_bytes());
    epb.extend((ts as u32).to_le_bytes());
    epb.extend((cut as u32).to_le_bytes());
    epb.extend((frame.len() as u32).to_le_bytes());
    epb.extend(&frame[..cut]);
    epb.resize(epb.len().next_multiple_of(4), 0);
    block(6, &epb)
}

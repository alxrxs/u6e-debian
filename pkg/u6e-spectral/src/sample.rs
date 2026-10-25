//! The samples ath11k writes to a radio's relay file (`spectral_scan0`):
//! `struct fft_sample_ath11k` of the kernel's `ath/spectral_common.h`, one
//! after another, each a type byte and a big-endian length, then the header
//! and one byte per in-band FFT bin. The driver has already cut the
//! hardware's reports down to this form, whatever the chip (`fft_sz`,
//! `summary_pad_sz` are its business), so one decoder serves every radio.
//!
//! A sample that does not parse is skipped and counted, never trusted: one of
//! another type or a malformed one by the length it states, and when that
//! length is beyond any sample the rest of what was read, since the stream's
//! framing is lost. What a read cut short waits for the next, so the buffer
//! never holds more than one read and one sample.

use std::io::{self, ErrorKind, Read};

/// `ATH_FFT_SAMPLE_ATH11K`.
const TYPE_ATH11K: u8 = 4;
/// The type byte and the length.
const TLV: usize = 3;
/// What follows the length up to the bins.
const HEADER: usize = 19;
/// The most in-band bins a radio reports: half of `max_fft_bins` (1024).
pub const MAX_BINS: usize = 512;
const MAX_SAMPLE: usize = TLV + HEADER + MAX_BINS;
/// The most taken from the relay file at one read, so one call is bounded
/// however fast the radio writes.
pub const READ_CAP: usize = 64 << 10;

/// One FFT sample, its fields in host order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample<'a> {
    pub width_mhz: u16,
    pub max_exp: u8,
    /// The centre of the scanned segment.
    pub freq1: u16,
    /// The in-band power, in dB above `noise`.
    pub rssi: i16,
    pub noise: i32,
    pub bins: &'a [u8],
}

/// What the stream held besides good samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Skipped {
    /// A sample of a type other than ath11k's.
    pub unknown: u64,
    /// An ath11k sample whose length, bin count, width or noise is wrong.
    pub malformed: u64,
    /// A length beyond any sample, and the rest of the read with it.
    pub lost: u64,
    /// A sample cut short at the end of the stream.
    pub truncated: u64,
}

/// Reads a relay file and cuts it into samples.
pub struct Decoder {
    buf: Vec<u8>,
    pub samples: u64,
    pub skipped: Skipped,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder {
            buf: Vec::with_capacity(READ_CAP + MAX_SAMPLE),
            samples: 0,
            skipped: Skipped::default(),
        }
    }
}

impl Decoder {
    /// Reads what `r` holds now, up to [`READ_CAP`], and hands each whole
    /// sample to `each`; the raw bytes read go to `raw` first. Returns the
    /// bytes read: 0 when the radio wrote nothing since.
    pub fn read(
        &mut self,
        r: &mut impl Read,
        raw: &mut impl FnMut(&[u8]),
        each: &mut impl FnMut(&Sample),
    ) -> io::Result<usize> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CAP, 0);
        let n = loop {
            match r.read(&mut self.buf[start..]) {
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => break 0,
                Err(e) => {
                    self.buf.truncate(start);
                    return Err(e);
                }
                Ok(n) => break n,
            }
        };
        self.buf.truncate(start + n);
        raw(&self.buf[start..]);
        self.cut(each);
        Ok(n)
    }

    /// Decodes `bytes` as if read from the relay file.
    #[cfg(test)]
    pub fn feed(&mut self, bytes: &[u8], each: &mut impl FnMut(&Sample)) {
        for chunk in bytes.chunks(READ_CAP) {
            self.buf.extend_from_slice(chunk);
            self.cut(each);
        }
    }

    /// The end of the stream: what is left is a sample cut short.
    pub fn finish(&mut self) {
        if !self.buf.is_empty() {
            self.skipped.truncated += 1;
            self.buf.clear();
        }
    }

    fn cut(&mut self, each: &mut impl FnMut(&Sample)) {
        let mut at = 0;
        while let Some(&[kind, hi, lo]) = self.buf.get(at..at + TLV) {
            let len = TLV + usize::from(u16::from_be_bytes([hi, lo]));
            if len > MAX_SAMPLE {
                self.skipped.lost += 1;
                at = self.buf.len();
                break;
            }
            let Some(tlv) = self.buf.get(at..at + len) else {
                break;
            };
            match (kind, parse(tlv)) {
                (TYPE_ATH11K, Some(s)) => {
                    self.samples += 1;
                    each(&s);
                }
                (TYPE_ATH11K, None) => self.skipped.malformed += 1,
                _ => self.skipped.unknown += 1,
            }
            at += len;
        }
        self.buf.drain(..at);
    }
}

/// The sample of one whole ath11k TLV, or `None` when its fields cannot be
/// one the driver writes.
fn parse(tlv: &[u8]) -> Option<Sample<'_>> {
    let h = tlv.get(TLV..TLV + HEADER)?;
    let bins = &tlv[TLV + HEADER..];
    let be16 = |i: usize| u16::from_be_bytes([h[i], h[i + 1]]);
    let width_mhz = u16::from(h[0]);
    let noise = i32::from_be_bytes([h[15], h[16], h[17], h[18]]);
    let ok = (16..=MAX_BINS).contains(&bins.len())
        && bins.len().is_power_of_two()
        && [20, 40, 80, 160].contains(&width_mhz)
        && (-128..0).contains(&noise);
    ok.then(|| Sample {
        width_mhz,
        max_exp: h[2],
        freq1: be16(3),
        rssi: be16(9) as i16,
        noise,
        bins,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// An ath11k sample as the driver writes it.
    pub fn sample(width: u8, freq1: u16, rssi: u16, noise: i32, bins: &[u8]) -> Vec<u8> {
        let mut s = vec![TYPE_ATH11K];
        s.extend(u16::try_from(HEADER + bins.len()).unwrap().to_be_bytes());
        s.extend([width, 3, 0]);
        s.extend(freq1.to_be_bytes());
        s.extend(0u16.to_be_bytes());
        s.extend(200u16.to_be_bytes());
        s.extend(rssi.to_be_bytes());
        s.extend(0x1234_5678u32.to_be_bytes());
        s.extend(noise.to_be_bytes());
        s.extend(bins);
        s
    }

    fn decode(bytes: &[u8]) -> (Vec<(u16, usize)>, Decoder) {
        let mut d = Decoder::default();
        let mut got = Vec::new();
        d.feed(bytes, &mut |s: &Sample| got.push((s.freq1, s.bins.len())));
        (got, d)
    }

    #[test]
    fn samples_decode_in_order() {
        let mut bytes = sample(80, 5775, 30, -96, &[7; 256]);
        bytes.extend(sample(20, 2472, 10, -95, &[1; 64]));
        let mut d = Decoder::default();
        let mut got = Vec::new();
        d.feed(&bytes, &mut |s: &Sample| {
            got.push((s.width_mhz, s.freq1, s.rssi, s.noise, s.bins.len()))
        });
        assert_eq!(got, [(80, 5775, 30, -96, 256), (20, 2472, 10, -95, 64)]);
        assert_eq!((d.samples, d.skipped), (2, Skipped::default()));
    }

    /// A read may end anywhere in a sample: the rest comes with the next.
    #[test]
    fn a_sample_split_across_reads_is_whole() {
        let bytes = sample(80, 5775, 30, -96, &[7; 256]);
        for cut in [1, 2, 3, 10, 22, 100, bytes.len() - 1] {
            let mut d = Decoder::default();
            let mut n = 0;
            d.feed(&bytes[..cut], &mut |_: &Sample| n += 1);
            assert_eq!(n, 0);
            d.feed(&bytes[cut..], &mut |_: &Sample| n += 1);
            assert_eq!((n, d.skipped), (1, Skipped::default()), "cut at {cut}");
        }
    }

    #[test]
    fn unknown_and_malformed_samples_are_skipped_and_counted() {
        let good = sample(80, 5775, 30, -96, &[7; 128]);
        let mut other = good.clone();
        other[0] = 3;
        let wrong_bins = sample(80, 5775, 30, -96, &[7; 100]);
        let wrong_width = sample(30, 5775, 30, -96, &[7; 128]);
        let no_noise = sample(80, 5775, 30, 0, &[7; 128]);
        let short = {
            let mut s = vec![TYPE_ATH11K];
            s.extend(5u16.to_be_bytes());
            s.extend([0; 5]);
            s
        };
        let bytes = [
            &other[..],
            &good,
            &wrong_bins,
            &wrong_width,
            &no_noise,
            &short,
            &good,
        ]
        .concat();
        let (got, d) = decode(&bytes);
        assert_eq!(got, [(5775, 128), (5775, 128)]);
        let want = Skipped {
            unknown: 1,
            malformed: 4,
            ..Skipped::default()
        };
        assert_eq!(d.skipped, want);
    }

    /// A length beyond any sample loses the framing: the rest of the read
    /// goes, counted, and the next read starts afresh.
    #[test]
    fn a_length_beyond_any_sample_drops_the_rest_of_the_read() {
        let good = sample(80, 5775, 30, -96, &[7; 128]);
        let mut bad = vec![TYPE_ATH11K, 0xff, 0xff];
        bad.extend(&good);
        let mut d = Decoder::default();
        let mut n = 0;
        d.feed(&bad, &mut |_: &Sample| n += 1);
        assert_eq!((n, d.skipped.lost), (0, 1));
        assert!(d.buf.is_empty());
        d.feed(&good, &mut |_: &Sample| n += 1);
        assert_eq!(n, 1);
    }

    #[test]
    fn a_sample_cut_short_at_the_end_is_counted() {
        let good = sample(80, 5775, 30, -96, &[7; 128]);
        let (_, mut d) = decode(&good[..40]);
        d.finish();
        assert_eq!(d.skipped.truncated, 1);
        assert!(d.buf.is_empty());
    }

    /// Whatever the bytes, the decoder neither panics nor keeps more than
    /// one read and one sample.
    #[test]
    fn garbage_never_panics_or_grows_the_buffer() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut d = Decoder::default();
        for _ in 0..200 {
            let chunk: Vec<u8> = (0..4096)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    // Mostly ath11k types and small lengths, to reach deep.
                    match x % 5 {
                        0 => TYPE_ATH11K,
                        1 => 0,
                        _ => x as u8,
                    }
                })
                .collect();
            d.feed(&chunk, &mut |s: &Sample| assert!(s.bins.len() <= MAX_BINS));
            assert!(d.buf.len() < MAX_SAMPLE);
        }
        assert_ne!(d.skipped, Skipped::default());
    }

    #[test]
    fn read_takes_what_the_file_holds_and_reports_it_raw() {
        let bytes = [
            sample(80, 5775, 30, -96, &[7; 128]),
            sample(80, 5775, 30, -96, &[9; 128]),
        ]
        .concat();
        let mut d = Decoder::default();
        let (mut raw, mut n) = (Vec::new(), 0);
        let mut r = &bytes[..];
        let got = d
            .read(&mut r, &mut |b| raw.extend(b), &mut |_: &Sample| n += 1)
            .unwrap();
        assert_eq!((got, n, raw), (bytes.len(), 2, bytes.clone()));
        let got = d.read(&mut r, &mut |_| {}, &mut |_: &Sample| n += 1);
        assert_eq!(got.unwrap(), 0);
    }

    /// 64 samples of a 5 GHz radio on 80 MHz (5775 MHz centre) in
    /// background mode, as its relay file gave them; two transmissions in.
    pub const RECORDED: &[u8] = include_bytes!("../tests/fixtures/radio5-80mhz.relay");

    #[test]
    fn the_recorded_samples_decode_whole() {
        let mut d = Decoder::default();
        let mut got = Vec::new();
        d.feed(RECORDED, &mut |s: &Sample| {
            got.push((s.width_mhz, s.freq1, s.noise, s.bins.len()));
        });
        d.finish();
        assert_eq!(got, vec![(80, 5775, -109, 256); 64]);
        assert_eq!(d.skipped, Skipped::default());
    }

    /// However the reads cut the recording, the same samples come out.
    #[test]
    fn the_recording_read_in_any_pieces_decodes_the_same() {
        let whole: Vec<u16> = {
            let mut v = Vec::new();
            Decoder::default().feed(RECORDED, &mut |s: &Sample| v.push(s.rssi as u16));
            v
        };
        for piece in [1, 7, 277, 278, 279, 4096] {
            let (mut d, mut v) = (Decoder::default(), Vec::new());
            for chunk in RECORDED.chunks(piece) {
                d.feed(chunk, &mut |s: &Sample| v.push(s.rssi as u16));
            }
            assert_eq!(v, whole, "pieces of {piece}");
        }
    }

    /// Each recorded sample is 278 B.
    const LEN: usize = 278;

    /// Decodes `bytes` and then the recording whole: the good samples, every
    /// one 80 MHz of 256 bins, and what was skipped.
    fn damaged(bytes: &[u8]) -> (usize, Skipped) {
        let mut d = Decoder::default();
        let mut good = 0;
        let mut each = |s: &Sample| {
            assert_eq!((s.width_mhz, s.bins.len()), (80, 256));
            good += 1;
        };
        d.feed(bytes, &mut each);
        d.finish();
        d.feed(RECORDED, &mut each);
        (good, d.skipped)
    }

    /// A sample of an unknown type is passed by its length, and one cut off
    /// at the end of the stream is counted.
    #[test]
    fn a_recorded_sample_of_another_type_or_cut_short_is_skipped() {
        let mut bytes = RECORDED.to_vec();
        bytes[3 * LEN] = 9;
        bytes.truncate(bytes.len() - 100);
        let want = Skipped {
            unknown: 1,
            truncated: 1,
            ..Skipped::default()
        };
        assert_eq!(damaged(&bytes), (62 + 64, want));
    }

    /// A sample that says it is 4 bytes short is malformed, and the next
    /// starts inside its bins: what follows is no sample, until a length
    /// beyond any sample drops the rest of the read. The next read is whole.
    #[test]
    fn a_recorded_sample_of_the_wrong_length_is_skipped_and_the_next_read_whole() {
        let mut bytes = RECORDED.to_vec();
        let at = 5 * LEN + 1;
        let short = u16::from_be_bytes([bytes[at], bytes[at + 1]]) - 4;
        bytes[at..at + 2].copy_from_slice(&short.to_be_bytes());
        let (good, skipped) = damaged(&bytes);
        assert_eq!(good, 5 + 64, "{skipped:?}");
        assert_eq!((skipped.malformed, skipped.lost), (1, 1));
    }
}

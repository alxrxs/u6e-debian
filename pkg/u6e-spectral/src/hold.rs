//! The samples of one frame period, held to the highest power each bin saw,
//! and the frame they make.
//!
//! A sample states the in-band power (`noise + rssi`, dBm) and each bin's
//! magnitude scaled down by `max_exp`; a bin's share of that power is its
//! squared magnitude over the sum of all of them, as FFT_eval (the tool that
//! comes with the driver's spectral support) computes it:
//!
//!   dBm(i) = noise + rssi + 20 log10(m(i)) - 10 log10(sum m(j)^2),
//!   m(i) = bin(i) << max_exp, a 0 counted as 1.

use std::sync::LazyLock;

use u6e_proto::msg::SpectrumFrame;

use crate::sample::Sample;

/// 20 log10 of each byte a bin holds, 0 taken as 1.
static DB20: LazyLock<[f32; 256]> =
    LazyLock::new(|| std::array::from_fn(|b| 20.0 * (b.max(1) as f32).log10()));
/// 20 log10(2): one step of `max_exp`.
const DB20_2: f32 = 6.020_6;

/// What the held samples cover; a sample of another segment starts afresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Segment {
    freq1: u16,
    width_mhz: u16,
    bins: usize,
}

#[derive(Default)]
pub struct Hold {
    segment: Option<Segment>,
    /// The highest dBm of each bin so far.
    peak: Vec<f32>,
    noise: i32,
}

impl Hold {
    pub fn add(&mut self, s: &Sample) {
        let segment = Segment {
            freq1: s.freq1,
            width_mhz: s.width_mhz,
            bins: s.bins.len(),
        };
        if self.segment != Some(segment) {
            self.segment = Some(segment);
            self.peak.clear();
            self.peak.resize(segment.bins, f32::MIN);
        }
        let scale = u32::from(s.max_exp.min(7));
        let squares: u64 = s
            .bins
            .iter()
            .map(|&b| (u64::from(b.max(1)) << scale).pow(2))
            .sum();
        let offset = (s.noise + i32::from(s.rssi)) as f32 + DB20_2 * scale as f32
            - 10.0 * (squares as f32).log10();
        for (p, &b) in self.peak.iter_mut().zip(s.bins) {
            *p = p.max(offset + DB20[usize::from(b)]);
        }
        self.noise = s.noise;
    }

    /// The frame of the samples held since the last, or `None` when none
    /// came; the hold starts empty again.
    pub fn take(&mut self, radio: &str, at_ms: u64) -> Option<SpectrumFrame> {
        let seg = self.segment.take()?;
        let width = f64::from(seg.width_mhz);
        let step = width / seg.bins as f64;
        let first = f64::from(seg.freq1) - width / 2.0 + step / 2.0;
        let bins = self
            .peak
            .iter()
            .map(|&p| p.round().clamp(-128.0, 127.0) as i8)
            .collect();
        Some(SpectrumFrame {
            radio: radio.to_owned(),
            at_ms,
            center_mhz: seg.freq1,
            width_mhz: seg.width_mhz,
            first_mhz_x10: (first * 10.0).round() as u32,
            step_khz: (step * 1000.0).round() as u32,
            bins,
            noise_dbm: self.noise.clamp(-128, 127) as i8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(bins: &[u8], rssi: i16) -> Sample<'_> {
        Sample {
            width_mhz: 80,
            max_exp: 0,
            freq1: 5775,
            rssi,
            noise: -96,
            bins,
        }
    }

    /// Equal bins share the in-band power equally: each is that power less
    /// 10 log10 of their number.
    #[test]
    fn equal_bins_split_the_in_band_power() {
        let mut h = Hold::default();
        h.add(&sample(&[10; 256], 20));
        let f = h.take("radio5", 7).unwrap();
        // -76 dBm over 256 bins: -76 - 24.08.
        assert!(f.bins.iter().all(|&b| b == -100), "{:?}", &f.bins[..4]);
        assert_eq!((f.radio.as_str(), f.at_ms, f.noise_dbm), ("radio5", 7, -96));
        assert_eq!((f.center_mhz, f.width_mhz, f.step_khz), (5775, 80, 313));
        // 5735 MHz plus half of 312.5 kHz.
        assert_eq!(f.first_mhz_x10, 57352);
        assert!(h.take("radio5", 8).is_none(), "the hold starts empty");
    }

    /// Each bin keeps the highest of the samples, not the last.
    #[test]
    fn the_peak_of_each_bin_is_held() {
        let mut low = [10; 64];
        let mut high = [10; 64];
        low[3] = 100;
        high[40] = 100;
        let mut h = Hold::default();
        h.add(&sample(&high, 20));
        h.add(&sample(&low, 20));
        let f = h.take("radio5", 0).unwrap();
        let peaks: Vec<usize> = (0..64).filter(|&i| f.bins[i] > f.bins[0]).collect();
        assert_eq!(peaks, [3, 40]);
        // A tone 20 dB above 63 others takes most of the power.
        assert!(f.bins[3] - f.bins[0] == 20, "{} {}", f.bins[3], f.bins[0]);
    }

    /// max_exp scales every bin alike: the shares, so the dBm, do not move.
    #[test]
    fn max_exp_leaves_the_shares_alone() {
        let bins: Vec<u8> = (0..128).map(|i| (i % 50 + 1) as u8).collect();
        let mut a = Hold::default();
        a.add(&sample(&bins, 20));
        let mut b = Hold::default();
        b.add(&Sample {
            max_exp: 3,
            ..sample(&bins, 20)
        });
        assert_eq!(a.take("r", 0), b.take("r", 0));
    }

    #[test]
    fn a_new_segment_starts_afresh_and_values_stay_in_range() {
        let mut h = Hold::default();
        h.add(&sample(&[200; 64], 20));
        h.add(&Sample {
            width_mhz: 160,
            freq1: 6185,
            rssi: 400,
            ..sample(&[0; 32], 0)
        });
        let f = h.take("radio6", 0).unwrap();
        assert_eq!((f.width_mhz, f.bins.len()), (160, 32));
        assert!(f.bins.iter().all(|&b| b == 127));
    }

    /// The recorded samples' frame, of the quiet ones and of all: the noise
    /// near the floor the radio reports less the 24 dB of 256 bins, and the
    /// two transmissions (rssi 27 and 28) lifting the whole channel.
    #[test]
    fn the_recorded_frame_shows_the_transmissions_above_the_noise() {
        let frame = |quiet_only: bool| {
            let mut h = Hold::default();
            crate::sample::Decoder::default().feed(
                crate::sample::tests::RECORDED,
                &mut |s: &Sample| {
                    if !quiet_only || s.rssi < 10 {
                        h.add(s);
                    }
                },
            );
            h.take("radio5", 0).unwrap()
        };
        let median = |f: &SpectrumFrame| {
            let mut b = f.bins.clone();
            b.sort_unstable();
            b[b.len() / 2]
        };
        let (quiet, f) = (frame(true), frame(false));
        assert_eq!((f.center_mhz, f.width_mhz, f.noise_dbm), (5775, 80, -109));
        assert!(
            (-128..=-120).contains(&median(&quiet)),
            "{}",
            median(&quiet)
        );
        assert!(median(&f) >= median(&quiet) + 10, "{}", median(&f));
        let top = *f.bins.iter().max().unwrap();
        assert!((-100..=-80).contains(&top), "{top}");
        // Postcard: the frame fits the 600 B a frame may take on the wire.
        let mut wire = Vec::new();
        u6e_proto::frame::write_frame(&mut wire, &u6e_proto::msg::AgentMsg::Spectrum(f)).unwrap();
        assert!(wire.len() <= 600, "{}", wire.len());
    }
}

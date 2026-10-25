//! The spectra the simulated radios' scans show, as the AP's spectral helper
//! sends them: ten frames a second, each the highest power per bin over its
//! tenth of a second, 3.2 bins per MHz of the radio's channel. Every channel
//! has its noise floor and the Wi-Fi bursts of its clients and neighbours; the
//! 6 GHz one is quiet but for them. Beside them, on the 5 GHz channels a
//! narrowband sender (a video link, say) comes and goes, drifting a little;
//! on 2.4 GHz a microwave oven runs for half of every minute, its hump swept
//! to and fro by the magnetron, and Bluetooth hops leave narrow blips.

use u6e_proto::msg::{Band, Radio, SpectrumFrame};

/// The centre of the channel `r` is on, which its width bonds the primary
/// channel into, in MHz.
pub fn center_mhz(r: &Radio) -> u16 {
    let k = (r.width_mhz / 20).max(1);
    let (base, first) = match r.band {
        Band::B24 => return 2407 + 5 * r.channel,
        Band::B5 => (5000, if r.channel >= 149 { 149 } else { 36 }),
        Band::B6 => (5950, 1),
    };
    let start = first + (r.channel - first) / (4 * k) * 4 * k;
    base + 5 * (start + 2 * (k - 1))
}

/// One frame of radio `r`, named `radio`, at `t` seconds into the replay;
/// `busy` is how much of the time its channel carries Wi-Fi, 0 to 1, and
/// `rng` gives numbers from -0.5 to 0.5.
pub fn frame(
    radio: &str,
    r: &Radio,
    busy: f64,
    t: f64,
    at_ms: u64,
    rng: &mut impl FnMut() -> f64,
) -> SpectrumFrame {
    let center = center_mhz(r);
    let width = f64::from(r.width_mhz);
    let n = usize::from(r.width_mhz) * 16 / 5;
    let step = width / n as f64;
    let low = f64::from(center) - width / 2.0;
    let freq = |i: usize| low + (i as f64 + 0.5) * step;
    let floor = f64::from(r.noise_dbm);
    let mut power: Vec<f64> = (0..n).map(|_| floor + 1.5 + 2.5 * rng()).collect();
    let add = |power: &mut Vec<f64>, f: &dyn Fn(f64) -> f64| {
        for (i, p) in power.iter_mut().enumerate() {
            *p = p.max(f(freq(i)));
        }
    };

    // Wi-Fi: a burst on the primary 20 MHz (beacons, acknowledgements) or
    // across the whole channel (data), its OFDM plateau falling off at the
    // edges of its occupied 18 MHz.
    let primary = match r.band {
        Band::B24 => 2407.0 + 5.0 * f64::from(r.channel),
        Band::B5 => 5000.0 + 5.0 * f64::from(r.channel),
        Band::B6 => 5950.0 + 5.0 * f64::from(r.channel),
    };
    let burst = |mid: f64, span: f64, level: f64| {
        move |f: f64| {
            let out = ((f - mid).abs() - span / 2.0).max(0.0);
            level - out * 9.0
        }
    };
    if rng() + 0.5 < busy {
        let level = -58.0 + 10.0 * rng();
        if rng() > 0.0 {
            add(&mut power, &burst(f64::from(center), width - 2.0, level));
        } else {
            add(&mut power, &burst(primary, 18.0, level - 4.0));
        }
    }
    // A neighbour's beacons now and then, weaker, on another 20 MHz.
    if r.width_mhz > 20 && rng() > 0.4 {
        let subchannels = width / 20.0;
        let which = ((rng() + 0.5) * subchannels).floor().min(subchannels - 1.0);
        let mid = low + 10.0 + 20.0 * which;
        add(&mut power, &burst(mid, 18.0, -74.0 + 4.0 * rng()));
    }

    match r.band {
        Band::B5 => {
            // On for 40 s of each minute, drifting by a few hundred kHz.
            if t % 60.0 < 40.0 {
                let at = f64::from(center) + width * 0.28 + 0.3 * (t / 7.0).sin();
                let level = -63.0 + rng();
                add(&mut power, &move |f: f64| {
                    level - ((f - at) / 0.35).powi(2) * 6.0
                });
            }
        }
        Band::B24 => {
            if t % 60.0 < 30.0 {
                // The magnetron's hump moves with its load, and its mains
                // cycle smears it over the tenth of a second.
                let at = 2457.0 + 6.0 * (t * 0.9).sin() + rng();
                let level = -44.0 + 3.0 * rng();
                add(&mut power, &move |f: f64| {
                    level - ((f - at) / 4.0).powi(2) * 8.0
                });
            }
            for _ in 0..2 {
                if rng() > 0.1 {
                    let at = 2402.0 + (rng() + 0.5) * 78.0;
                    let level = -70.0 + 6.0 * rng();
                    add(&mut power, &move |f: f64| {
                        level - ((f - at) / 0.5).powi(2) * 10.0
                    });
                }
            }
        }
        Band::B6 => {}
    }

    SpectrumFrame {
        radio: radio.into(),
        at_ms,
        center_mhz: center,
        width_mhz: r.width_mhz,
        first_mhz_x10: ((low + step / 2.0) * 10.0).round() as u32,
        step_khz: (step * 1000.0).round() as u32,
        bins: power
            .iter()
            .map(|p| p.round().clamp(-127.0, 0.0) as i8)
            .collect(),
        noise_dbm: r.noise_dbm,
    }
}

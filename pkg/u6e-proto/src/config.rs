//! A Wi-Fi configuration's identity and authority: the hash it is known by,
//! and the deploy runner's Ed25519 signature over it, which the AP checks
//! against the runner's key its image pins. The controller relays
//! configurations but holds no key that signs one, so it cannot make an AP
//! run one the runner did not render. The sequence number is the runner's
//! signing time in milliseconds: the AP takes one past both the last it
//! applied and its image's build time ([`replayed`]), and before its signed
//! `not_after`, [`VALIDITY_MS`] later ([`expired`]), while its clock is
//! synchronized.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};

use crate::PROTOCOL;
use crate::msg::{RadioConfig, SignedConfig};

/// Sets what the runner signs here apart from anything else its key signs
/// (its TLS handshakes).
const CONTEXT: &str = "u6e wifi config";

/// How long a signed configuration may apply: every one the runner signs is
/// applied at once (a live apply or a re-push), so one held back longer is
/// a replay.
pub const VALIDITY_MS: u64 = 10 * 60 * 1000;

/// The hash a configuration is known by: SHA-256 of the postcard encoding of
/// its radios, in order.
pub fn config_sha256(radios: &[RadioConfig]) -> [u8; 32] {
    // Into a Vec, of types that always encode: it cannot fail.
    let bytes = postcard::to_stdvec(radios).unwrap_or_default();
    let mut h = [0; 32];
    h.copy_from_slice(digest(&SHA256, &bytes).as_ref());
    h
}

/// The bytes the runner signs: [`CONTEXT`], the protocol, the AP, the
/// sequence number, the end of validity and the hash, postcard-encoded.
pub fn payload(protocol: u16, ap: &str, seq: u64, not_after: u64, sha256: &[u8; 32]) -> Vec<u8> {
    postcard::to_stdvec(&(CONTEXT, protocol, ap, seq, not_after, sha256)).unwrap_or_default()
}

/// `radios`, the configuration of `ap` signed with `key` at `seq` (the
/// signing time in milliseconds), valid for [`VALIDITY_MS`].
pub fn sign(key: &Ed25519KeyPair, ap: &str, seq: u64, radios: Vec<RadioConfig>) -> SignedConfig {
    let sha256 = config_sha256(&radios);
    let not_after = seq + VALIDITY_MS;
    let signature = key
        .sign(&payload(PROTOCOL, ap, seq, not_after, &sha256))
        .as_ref()
        .to_vec();
    SignedConfig {
        ap: ap.to_owned(),
        seq,
        not_after,
        sha256,
        radios,
        signature,
    }
}

/// Checks that `c` is a configuration for `ap`, whole, signed by the runner
/// whose public key is `runner`; the error says what it is not.
pub fn verify(runner: &[u8; 32], ap: &str, c: &SignedConfig) -> Result<(), String> {
    if c.ap != ap {
        return Err(format!("for another AP ({:.64})", c.ap));
    }
    if config_sha256(&c.radios) != c.sha256 {
        return Err("the configuration does not match its SHA-256".into());
    }
    UnparsedPublicKey::new(&ED25519, runner)
        .verify(
            &payload(PROTOCOL, &c.ap, c.seq, c.not_after, &c.sha256),
            &c.signature,
        )
        .map_err(|_| "not signed by the deploy runner".into())
}

/// Why sequence number `seq` may not apply when `last` (named `what`) was
/// the last one and `floor` the image's build time (`Hello::built_ms`): a
/// replay unless past both. A reboot forgets the last one applied, not the
/// image's build time, so no configuration signed before the image was built
/// ever applies on it.
pub fn replayed(seq: u64, last: u64, what: &str, floor: u64) -> Option<String> {
    let (bound, what) = if last >= floor {
        (last, what)
    } else {
        (floor, "this image's build time")
    };
    (seq <= bound).then(|| format!("replayed: sequence {seq} is not past {bound}, {what}"))
}

/// Why `c` may not apply at `now` (milliseconds since the Unix epoch, `None`
/// while the clock is not synchronized): past its `not_after`, or no clock
/// to tell.
pub fn expired(c: &SignedConfig, now: Option<u64>) -> Option<String> {
    let Some(now) = now else {
        return Some("the clock is not synchronized, so no configuration applies".into());
    };
    (now > c.not_after).then(|| format!("expired: valid until {}, now {now}", c.not_after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

    use crate::msg::Band;

    /// Throwaway test keys: the runner's, and another.
    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn public(k: &Ed25519KeyPair) -> [u8; 32] {
        k.public_key().as_ref().try_into().unwrap()
    }

    fn radios() -> Vec<RadioConfig> {
        vec![RadioConfig {
            radio: Band::B5,
            text: "interface=wlan5\n".into(),
            txpower_dbm: 23,
        }]
    }

    #[test]
    fn a_configuration_the_runner_signed_for_this_ap_passes() {
        let runner = key(1);
        let c = sign(&runner, "ap1", 7, radios());
        assert_eq!(c.signature.len(), 64);
        assert_eq!(verify(&public(&runner), "ap1", &c), Ok(()));
    }

    /// Whatever is changed after signing, or signed by another key, fails.
    #[test]
    fn a_forged_or_altered_configuration_fails() {
        let runner = key(1);
        let pk = public(&runner);
        let good = sign(&runner, "ap1", 7, radios());
        let fails = |c: &SignedConfig| verify(&pk, "ap1", c).unwrap_err();

        assert_eq!(
            fails(&sign(&key(2), "ap1", 7, radios())),
            "not signed by the deploy runner"
        );
        assert_eq!(
            fails(&SignedConfig {
                signature: Vec::new(),
                ..good.clone()
            }),
            "not signed by the deploy runner"
        );
        assert_eq!(
            fails(&SignedConfig {
                seq: 8,
                ..good.clone()
            }),
            "not signed by the deploy runner"
        );
        // Its validity stretched.
        assert_eq!(
            fails(&SignedConfig {
                not_after: good.not_after + 1,
                ..good.clone()
            }),
            "not signed by the deploy runner"
        );
        let mut text = good.clone();
        text.radios[0].text.push('#');
        assert_eq!(fails(&text), "the configuration does not match its SHA-256");
        let mut power = good.clone();
        power.radios[0].txpower_dbm = 30;
        assert_eq!(
            fails(&power),
            "the configuration does not match its SHA-256"
        );
        let mut rehashed = power.clone();
        rehashed.sha256 = config_sha256(&rehashed.radios);
        assert_eq!(fails(&rehashed), "not signed by the deploy runner");
        // Another AP's configuration, its name changed or not.
        let other = sign(&runner, "ap2", 7, radios());
        assert_eq!(fails(&other), "for another AP (ap2)");
        assert_eq!(
            fails(&SignedConfig {
                ap: "ap1".into(),
                ..other
            }),
            "not signed by the deploy runner"
        );
    }

    /// The signed bytes cover the protocol: a configuration signed for
    /// another protocol's agents is not one for this.
    #[test]
    fn the_payload_binds_the_protocol() {
        let h = [9; 32];
        assert_ne!(
            payload(PROTOCOL, "ap1", 1, 2, &h),
            payload(PROTOCOL + 1, "ap1", 1, 2, &h)
        );
        let runner = key(1);
        let mut c = sign(&runner, "ap1", 1, radios());
        c.signature = runner
            .sign(&payload(PROTOCOL + 1, "ap1", 1, c.not_after, &c.sha256))
            .as_ref()
            .to_vec();
        assert!(verify(&public(&runner), "ap1", &c).is_err());
    }

    #[test]
    fn past_the_last_and_the_images_build_time() {
        let last = "the last installed";
        assert_eq!(replayed(11, 10, last, 5), None);
        assert_eq!(
            replayed(10, 10, last, 5).as_deref(),
            Some("replayed: sequence 10 is not past 10, the last installed")
        );
        assert_eq!(
            replayed(8, 0, last, 9).as_deref(),
            Some("replayed: sequence 8 is not past 9, this image's build time")
        );
        assert_eq!(replayed(1, 0, last, 0), None);
    }

    /// A configuration applies until its `not_after`, and only by a clock
    /// that is synchronized.
    #[test]
    fn valid_for_ten_minutes_by_a_synchronized_clock() {
        let c = sign(&key(1), "ap1", 1_000, radios());
        assert_eq!(c.not_after, 1_000 + VALIDITY_MS);
        assert_eq!(expired(&c, Some(1_000)), None);
        assert_eq!(expired(&c, Some(c.not_after)), None);
        assert_eq!(
            expired(&c, Some(c.not_after + 1)).as_deref(),
            Some("expired: valid until 601000, now 601001")
        );
        assert_eq!(
            expired(&c, None).as_deref(),
            Some("the clock is not synchronized, so no configuration applies")
        );
    }

    #[test]
    fn the_text_stays_out_of_debug() {
        let shown = format!("{:?}", radios()[0]);
        assert!(!shown.contains("interface"), "{shown}");
        assert!(shown.contains("<16 bytes>"));
    }
}

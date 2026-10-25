//! The deploy runner's process, its local callers' end, and its stage
//! helper.
//!
//!   u6e-deploy [--config <path>]
//!   u6e-deploy apply <ap> [--config <path>]       < <u6e-wifi script>
//!   u6e-deploy rollout <ap> <image> [--config <path>]
//!   u6e-deploy --stage-helper [--config <path>]
//!
//! Without a command it is the runner, until stopped. `apply` reads the
//! script `boot/wifi-up.sh --print` renders for the AP, has the runner sign
//! its radios' configuration and the AP apply it, and exits 0 only when the
//! AP applied exactly that configuration. `rollout` has the runner roll a
//! kept image out to the AP, printing its log, and exits 0 only when the AP
//! passed the health gate. `--stage-helper` is the root helper, serving the
//! socket systemd passes it (see `stage`). The default
//! configuration is /etc/u6e-deploy/config.toml.

use std::fs;
use std::future;
use std::io::{self, Read};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::process::ExitCode;

use u6e_deploy::config::Config;
use u6e_deploy::stage::{self, group_id};
use u6e_deploy::{local, script};
use u6e_proto::frame::zeroize;
use u6e_proto::mac;
use u6e_proto::tls::Identity;

const DEFAULT_CONFIG: &str = "/etc/u6e-deploy/config.toml";

const USAGE: &str = "usage: u6e-deploy [apply <ap> | rollout <ap> <image> | --stage-helper] \
                     [--config <path>]";

/// The command and its operands, and the configuration's path.
fn args() -> Option<(Vec<String>, String)> {
    let mut words = Vec::new();
    let mut config = DEFAULT_CONFIG.to_owned();
    let mut a = std::env::args().skip(1);
    while let Some(w) = a.next() {
        if w == "--config" {
            config = a.next()?;
        } else {
            words.push(w);
        }
    }
    Some((words, config))
}

fn load(path: &str) -> Result<Config, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    Config::parse(&text).map_err(|e| format!("{path}: {e}"))
}

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

fn main() -> ExitCode {
    let Some((words, path)) = args() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    if !matches!(
        words.as_slice(),
        [] | ["apply", _] | ["rollout", _, _] | ["--stage-helper"]
    ) {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let r = load(&path).and_then(|config| match words.as_slice() {
        ["apply", ap] => apply(&config, ap),
        ["rollout", ap, image] => rollout(&config, ap, image),
        ["--stage-helper"] => stage_helper(config),
        _ => run(config),
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("u6e-deploy: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The runner, until stopped.
fn run(config: Config) -> Result<(), String> {
    let read =
        |p: &std::path::Path| fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let identity = Identity::from_pem(&read(&config.tls_key)?)
        .map_err(|e| format!("{}: {e}", config.tls_key.display()))?;
    let mut pem = read(&config.signing_key)?;
    let key = u6e_deploy::signing_key(&pem, &identity);
    // SAFETY: zeros are valid UTF-8, and the PEM is not read after.
    zeroize(unsafe { pem.as_mut_vec() });
    let key = key.map_err(|e| format!("{}: {e}", config.signing_key.display()))?;
    let rt = runtime().map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        use aws_lc_rs::signature::KeyPair;
        let signs = mac::hex(key.public_key().as_ref());
        let runner = u6e_deploy::start(config, identity, key)
            .await
            .map_err(|e| e.to_string())?;
        eprintln!(
            "u6e-deploy: serving {} for {} APs, signing as {signs}, protocol {}",
            runner.config.socket.display(),
            runner.config.aps.len(),
            u6e_proto::PROTOCOL
        );
        future::pending::<Result<(), String>>().await
    })
}

/// Applies the configuration of the script on stdin to `ap`.
fn apply(config: &Config, ap: &str) -> Result<(), String> {
    let mut script = String::new();
    io::stdin()
        .read_to_string(&mut script)
        .map_err(|e| format!("stdin: {e}"))?;
    let radios = script::radios(&script);
    // SAFETY: zeros are valid UTF-8, and the script is not read after.
    zeroize(unsafe { script.as_mut_vec() });
    let radios = radios?;
    let rt = runtime().map_err(|e| format!("runtime: {e}"))?;
    let done = rt.block_on(local::apply(&config.socket, ap, radios))?;
    println!("{done}");
    Ok(())
}

/// Rolls `image` out to `ap`, printing its log.
fn rollout(config: &Config, ap: &str, image: &str) -> Result<(), String> {
    let rt = runtime().map_err(|e| format!("runtime: {e}"))?;
    let print = |l: &str| println!("{ap}: {l}");
    let done = rt.block_on(local::rollout(&config.socket, ap, image, print))?;
    println!("{ap}: {done}");
    Ok(())
}

/// The root helper: the connections to the socket systemd passes it (the
/// first descriptor past stderr, `LISTEN_FDS`), each from root or the
/// configured group alone.
fn stage_helper(config: Config) -> Result<(), String> {
    let etc_group = fs::read_to_string("/etc/group").unwrap_or_default();
    let gid = group_id(&etc_group, &config.rollout.group)
        .ok_or_else(|| format!("no group {}", config.rollout.group))?;
    let ours = std::env::var("LISTEN_PID").ok() == Some(std::process::id().to_string());
    if !ours || std::env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
        return Err("stage helper: not started by its socket".into());
    }
    // SAFETY: systemd passes the listening socket as descriptor 3, which
    // nothing else here uses.
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    stage::run(config, listener, gid).map_err(|e| format!("stage helper: {e}"))
}

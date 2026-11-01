//! The controller's process, and root's local commands of it.
//!
//!   u6e-controller [--config <path>]
//!   u6e-controller apply <ap> [--config <path>]       < <u6e-wifi script>
//!   u6e-controller image add <dir> [--config <path>]
//!   u6e-controller hold <ap> <reason> [--config <path>]
//!   u6e-controller release <ap> [--config <path>]
//!
//! Without a command it is the controller, until stopped. `apply` reads the
//! script `boot/wifi-up.sh --print` renders for the AP, has the controller
//! sign its radios' configuration and send it, and exits 0 only when the AP
//! applied exactly that configuration, printing how each radio took it.
//! `image add` hands the controller the image in `<dir>` (an image as the
//! build keeps it, `images/<id>/`), which it keeps under the directory's
//! name once every file is the one its `MANIFEST` lists. `hold` keeps the
//! controller off `ap` for 30 minutes (no rollout of any AP, no live
//! configuration or radio command to it) while something else reboots it,
//! refused while a rollout runs; `release` ends that. Each reaches the
//! running controller on its local socket. The default configuration is
//! /etc/wifi-controller/config.toml.

use std::fs;
use std::future;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use u6e_controller::agents::Timing;
use u6e_controller::config::Config;
use u6e_controller::names::System;
use u6e_controller::{local, script};
use u6e_proto::frame::zeroize;
use u6e_proto::tls::Identity;

const DEFAULT_CONFIG: &str = "/etc/wifi-controller/config.toml";

const USAGE: &str = "usage: u6e-controller [apply <ap> | image add <dir> | hold <ap> <reason> | \
                     release <ap>] [--config <path>]";

/// The command's words and the configuration's path.
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

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))
}

fn main() -> ExitCode {
    let Some((words, path)) = args() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    if !matches!(
        words.as_slice(),
        [] | ["apply", _] | ["image", "add", _] | ["hold", _, _] | ["release", _]
    ) {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let r = load(&path).and_then(|config| match words.as_slice() {
        ["apply", ap] => apply(&config, ap),
        ["image", "add", dir] => image_add(&config, Path::new(dir)),
        ["hold", ap, reason] => hold(&config, ap, Some(reason)),
        ["release", ap] => hold(&config, ap, None),
        _ => run(&config),
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("u6e-controller: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The controller, until stopped.
fn run(config: &Config) -> Result<(), String> {
    let pem =
        fs::read_to_string(&config.key).map_err(|e| format!("{}: {e}", config.key.display()))?;
    let identity =
        Identity::from_pem(&pem).map_err(|e| format!("{}: {e}", config.key.display()))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(async {
        let c = u6e_controller::start(config, &identity, Timing::default(), Arc::new(System), None)
            .await
            .map_err(|e| e.to_string())?;
        eprintln!(
            "u6e-controller: agents on {}, http on {}, metrics on {}, {} APs configured, \
             configurations {}, rollouts {}, protocol {}",
            c.agents,
            c.http,
            c.metrics,
            config.aps.len(),
            if config.configs.is_some() {
                "signed"
            } else {
                "off"
            },
            if config.rollouts.is_some() {
                "on"
            } else {
                "off"
            },
            u6e_proto::PROTOCOL
        );
        future::pending::<Result<(), String>>().await
    })
}

/// Applies the configuration of the script on stdin to `ap`.
fn apply(config: &Config, ap: &str) -> Result<(), String> {
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| format!("stdin: {e}"))?;
    let radios = script::radios(&text);
    // SAFETY: zeros are valid UTF-8, and the script is not read after.
    zeroize(unsafe { text.as_mut_vec() });
    let radios = radios?;
    let done = runtime()?.block_on(local::apply(&config.socket, ap, radios))?;
    println!("{done}");
    Ok(())
}

/// Holds `ap` for `reason`, or releases it.
fn hold(config: &Config, ap: &str, reason: Option<&str>) -> Result<(), String> {
    let done = runtime()?.block_on(local::hold(&config.socket, ap, reason))?;
    println!("{done}");
    Ok(())
}

/// Hands the controller the image in `dir`.
fn image_add(config: &Config, dir: &Path) -> Result<(), String> {
    let done = runtime()?.block_on(local::add_image(&config.socket, dir))?;
    println!("{done}");
    Ok(())
}

//! The controller's process: reads its configuration and key, then serves
//! until stopped.
//!
//!   u6e-controller [--config /etc/wifi-controller/config.toml]

use std::fs;
use std::future;
use std::path::PathBuf;
use std::process::ExitCode;

use u6e_controller::agents::Timing;
use u6e_controller::config::Config;
use u6e_proto::tls::Identity;

const DEFAULT_CONFIG: &str = "/etc/wifi-controller/config.toml";

fn config_path() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (None, _, _) => Some(DEFAULT_CONFIG.into()),
        (Some("--config"), Some(path), None) => Some(path.into()),
        _ => None,
    }
}

/// The configuration and the controller's identity, or why not.
fn load(path: &PathBuf) -> Result<(Config, Identity), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config = Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let pem =
        fs::read_to_string(&config.key).map_err(|e| format!("{}: {e}", config.key.display()))?;
    let identity =
        Identity::from_pem(&pem).map_err(|e| format!("{}: {e}", config.key.display()))?;
    Ok((config, identity))
}

fn main() -> ExitCode {
    let Some(path) = config_path() else {
        eprintln!("usage: u6e-controller [--config <path>]");
        return ExitCode::from(2);
    };
    let (config, identity) = match load(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("u6e-controller: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("u6e-controller: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        match u6e_controller::start(&config, &identity, Timing::default()).await {
            Ok(c) => {
                eprintln!(
                    "u6e-controller: agents on {}, http on {}, metrics on {}, {} APs configured",
                    c.agents,
                    c.http,
                    c.metrics,
                    config.aps.len()
                );
                future::pending::<ExitCode>().await
            }
            Err(e) => {
                eprintln!("u6e-controller: listen: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

//! Offline vanity-address search for TON wallets.
//!
//! Generates random recovery phrases for the chosen wallet kind (Telegram, V4R2, V5R1 or
//! Ledger, see `wallet.rs`) and derives each address exactly as that wallet does.
//! Telegram candidates take their anchor key from wallet-engine, and every hit is re-checked
//! through its `WalletLifecycle::import_wallet`, the code path the Telegram app runs on import.
//! Nothing touches the network; secrets are never written to disk.
//!
//! Usage: vanity-ton-wallet-crafter [--config FILE] [--wallet KIND] [--threads N] [SUFFIX...]
//! Targets come from `targets.toml`; options and suffixes on the command line override it.

mod wallet;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Deserialize;
use wallet_engine::{
    JournalCompareExchange, JournalCompareExchangeResult, JournalHostError, JournalHostErrorKind,
    JournalKey, JournalRecord, Network, ProtectedSecretHostError, ProtectedSecretHostErrorKind,
    ProtectedSecretRead, ProtectedSecretRef, ProtectedSecretStore, TonAddressFormat, WalletPlatformHost,
};

use wallet::{Candidate, Deriver, WalletKind};

const DEFAULT_CONFIG: &str = "targets.toml";

/// A host that keeps nothing: import "stores" the phrase, we drop it.
pub(crate) struct DiscardHost;

#[async_trait]
impl WalletPlatformHost for DiscardHost {
    async fn read_protected_secret(
        &self,
        _request: ProtectedSecretRead,
    ) -> Result<Vec<u8>, ProtectedSecretHostError> {
        Err(ProtectedSecretHostError::Failed {
            kind: ProtectedSecretHostErrorKind::NotFound,
            diagnostic: "discard host stores nothing".to_owned(),
        })
    }

    async fn store_protected_secret(
        &self,
        _request: ProtectedSecretStore,
    ) -> Result<(), ProtectedSecretHostError> {
        Ok(())
    }

    async fn delete_protected_secret(
        &self,
        _secret_ref: ProtectedSecretRef,
    ) -> Result<(), ProtectedSecretHostError> {
        Ok(())
    }

    async fn load_journal(&self, _key: JournalKey) -> Result<Option<JournalRecord>, JournalHostError> {
        Ok(None)
    }

    async fn compare_exchange_journal(
        &self,
        _mutation: JournalCompareExchange,
    ) -> Result<JournalCompareExchangeResult, JournalHostError> {
        Err(JournalHostError::Failed {
            kind: JournalHostErrorKind::Other,
            diagnostic: "discard host has no journal".to_owned(),
        })
    }
}

/// `targets.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "default_wallet")]
    wallet: String,
    #[serde(default = "default_network")]
    network: String,
    #[serde(default)]
    suffixes: Vec<String>,
    #[serde(default)]
    case_insensitive: bool,
}

fn default_wallet() -> String {
    "telegram".to_owned()
}

fn default_network() -> String {
    "mainnet".to_owned()
}

struct Args {
    kind: WalletKind,
    network: Network,
    threads: usize,
    suffixes: Vec<String>,
    case_insensitive: bool,
}

fn parse_args() -> Args {
    let mut config_path: Option<PathBuf> = None;
    let mut cli_wallet: Option<String> = None;
    let mut threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut cli_suffixes = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = Some(
                    args.next()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| exit_usage("--config needs a file path")),
                );
            }
            "--wallet" => {
                cli_wallet = Some(args.next().unwrap_or_else(|| exit_usage("--wallet needs a kind")));
            }
            "--threads" => {
                threads = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|&n| n > 0)
                    .unwrap_or_else(|| exit_usage("--threads needs a positive number"));
            }
            "-h" | "--help" => exit_usage(""),
            s if s.starts_with('-') && !s.starts_with("-_") && s.len() > 1 && s != "-" => {
                exit_usage(&format!("unknown option {s}"))
            }
            s => cli_suffixes.push(s.to_owned()),
        }
    }

    // An explicit --config must exist; the default one may be absent when suffixes come from the CLI.
    let path = config_path.clone().unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let config = match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str::<Config>(&text)
            .unwrap_or_else(|e| exit_usage(&format!("{}: {e}", path.display()))),
        Err(e) if config_path.is_some() || cli_suffixes.is_empty() => {
            exit_usage(&format!("cannot read {}: {e}", path.display()))
        }
        Err(_) => Config {
            wallet: default_wallet(),
            network: default_network(),
            suffixes: Vec::new(),
            case_insensitive: false,
        },
    };

    let wallet = cli_wallet.unwrap_or(config.wallet);
    let kind = WalletKind::parse(&wallet)
        .unwrap_or_else(|| exit_usage(&format!("wallet must be {}, got {wallet:?}", WalletKind::NAMES)));
    let network = match config.network.as_str() {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        other => exit_usage(&format!("network must be \"mainnet\" or \"testnet\", got {other:?}")),
    };
    let suffixes = if cli_suffixes.is_empty() { config.suffixes } else { cli_suffixes };
    if suffixes.is_empty() {
        exit_usage("no suffixes: list them in targets.toml or on the command line");
    }
    for s in &suffixes {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            exit_usage(&format!("suffix {s:?} has characters outside base64url [A-Za-z0-9_-]"));
        }
    }
    let suffixes = if config.case_insensitive {
        suffixes.iter().map(|s| s.to_ascii_lowercase()).collect()
    } else {
        suffixes
    };
    Args { kind, network, threads, suffixes, case_insensitive: config.case_insensitive }
}

fn exit_usage(error: &str) -> ! {
    if !error.is_empty() {
        eprintln!("error: {error}");
    }
    eprintln!(
        "usage: vanity-ton-wallet-crafter [--config FILE] [--wallet KIND] [--threads N] [SUFFIX...]"
    );
    eprintln!("       KIND is {}", WalletKind::NAMES);
    eprintln!("       targets are read from {DEFAULT_CONFIG}; command-line values override it");
    std::process::exit(if error.is_empty() { 0 } else { 2 });
}

/// Probability that a random address ends with `suffix` (64 base64url symbols per char).
fn suffix_probability(suffix: &str, case_insensitive: bool) -> f64 {
    suffix
        .bytes()
        .map(|b| if case_insensitive && b.is_ascii_alphabetic() { 2.0 / 64.0 } else { 1.0 / 64.0 })
        .product()
}

fn matches(address: &str, suffixes: &[String], case_insensitive: bool) -> bool {
    suffixes.iter().any(|s| {
        address.len() >= s.len()
            && if case_insensitive {
                address[address.len() - s.len()..].eq_ignore_ascii_case(s)
            } else {
                address.ends_with(s.as_str())
            }
    })
}

fn main() {
    let args = parse_args();
    let deriver = Arc::new(Deriver::new(args.kind, args.network));
    deriver.self_test();

    // Expected attempts for "any of the suffixes".
    let hit_probability: f64 =
        args.suffixes.iter().map(|s| suffix_probability(s, args.case_insensitive)).sum();
    let expected = 1.0 / hit_probability;
    eprintln!(
        "searching {:?}{} for {} on {:?} with {} threads; expected ~{:.2}M attempts",
        args.suffixes,
        if args.case_insensitive { " (case-insensitive)" } else { "" },
        args.kind.describe(),
        args.network,
        args.threads,
        expected / 1e6
    );

    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let ambiguous = Arc::new(AtomicU64::new(0));
    let result: Arc<Mutex<Option<Candidate>>> = Arc::new(Mutex::new(None));
    let suffixes = Arc::new(args.suffixes);

    let workers: Vec<_> = (0..args.threads)
        .map(|_| {
            let (deriver, found, attempts, ambiguous, result, suffixes) = (
                Arc::clone(&deriver),
                Arc::clone(&found),
                Arc::clone(&attempts),
                Arc::clone(&ambiguous),
                Arc::clone(&result),
                Arc::clone(&suffixes),
            );
            let case_insensitive = args.case_insensitive;
            std::thread::spawn(move || {
                while !found.load(Ordering::Relaxed) {
                    let candidate = deriver.derive(deriver.random_words());
                    attempts.fetch_add(1, Ordering::Relaxed);
                    if matches(&candidate.address, &suffixes, case_insensitive) {
                        if !deriver.is_unambiguous(&candidate.words) {
                            ambiguous.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if !found.swap(true, Ordering::SeqCst) {
                            *result.lock().unwrap() = Some(candidate);
                        }
                        return;
                    }
                }
            })
        })
        .collect();

    let start = Instant::now();
    let mut last_report = start;
    while !found.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        if last_report.elapsed() >= Duration::from_secs(10) {
            last_report = Instant::now();
            let elapsed = start.elapsed().as_secs_f64();
            let n = attempts.load(Ordering::Relaxed) as f64;
            let rate = n / elapsed;
            eprintln!(
                "  {:>6.0}s  {:>8.3}M attempts  {:>7.0}/s  ~{:.0} min average total",
                elapsed,
                n / 1e6,
                rate,
                expected / rate / 60.0
            );
        }
    }
    for worker in workers {
        worker.join().expect("worker panicked");
    }

    let hit = result.lock().unwrap().take().expect("match was recorded");
    let raw = deriver.confirm(&hit);
    let bounceable = wallet_engine::convert_ton_address(
        hit.address.clone(),
        TonAddressFormat::UserFriendly { bounceable: true, testnet: args.network == Network::Testnet },
    )
    .expect("address conversion failed");

    eprintln!(
        "found after {:.0}s, {} attempts ({} ambiguous hits skipped)\n",
        start.elapsed().as_secs_f64(),
        attempts.load(Ordering::Relaxed),
        ambiguous.load(Ordering::Relaxed)
    );
    println!(
        "RECOVERY PHRASE ({} words, {}; write it down, then clear this terminal):",
        hit.words.len(),
        args.kind.describe()
    );
    println!("  {}\n", hit.words.join(" "));
    println!("address (non-bounceable, as wallets show it): {}", hit.address);
    println!("address (bounceable):                         {bounceable}");
    println!("address (raw):                                {raw}");
    println!("public key:                                   {}", wallet::hex(&hit.public_key));
    println!("\nBefore funding it: {}, and confirm it shows this address.", args.kind.import_hint());
}

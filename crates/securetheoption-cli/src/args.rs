//! The command line: one subcommand per step of a quote's life.
//!
//! The shape mirrors `chia-sdk-cli` (`crates/chia-sdk-cli/src/args.rs:6-11`): a clap `Parser` enum with
//! one tuple variant per subcommand. `quote` is the only top-level command, because every subcommand
//! operates on a quote.

use std::path::PathBuf;

use chia_wallet_sdk::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use securetheoption::OfferFormat;

/// Prepare, seal and check presigned option-mint offers.
#[derive(Debug, Parser)]
#[command(name = "securetheoption", version)]
pub enum Command {
    /// Precompute a quote, seal it into an offer, verify an offer, and manage the quote book.
    #[command(subcommand)]
    Quote(QuoteCommand),
}

/// The quote lifecycle.
#[derive(Debug, Subcommand)]
pub enum QuoteCommand {
    Prepare(PrepareCommand),
    Create(CreateCommand),
    Seal(SealCommand),
    Verify(VerifyCommand),
    List(ListCommand),
    Requote(RequoteCommand),
    Retire(RetireCommand),
}

/// The Chia network whose domain separation constants and address prefix apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Network {
    /// Chia mainnet, using the `xch` address prefix.
    Mainnet,
    /// The testnet11 network, using the `txch` address prefix.
    Testnet11,
}

impl Network {
    /// The bech32m prefix addresses on this network use.
    pub fn address_prefix(self) -> &'static str {
        match self {
            Self::Mainnet => "xch",
            Self::Testnet11 => "txch",
        }
    }

    /// The aggregated-signature domain separation constants of this network.
    ///
    /// `AGG_SIG_ME` messages are only valid on the network whose additional data was signed, so the
    /// required-signature material has to be computed with the constants the node uses.
    pub fn agg_sig_constants(self) -> AggSigConstants {
        match self {
            Self::Mainnet => AggSigConstants::from(&*MAINNET_CONSTANTS),
            Self::Testnet11 => AggSigConstants::from(&*TESTNET11_CONSTANTS),
        }
    }
}

/// How `seal` encodes the offer it writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// A bech32 `offer1…` string wrapping a zlib-compressed spend bundle: what wallets import.
    #[default]
    Offer,
    /// The spend bundle as JSON, for signers and for hand inspection.
    Json,
}

impl From<Format> for OfferFormat {
    fn from(format: Format) -> Self {
        match format {
            Format::Offer => Self::Offer,
            Format::Json => Self::Json,
        }
    }
}

/// Resolve a friendly draft into terms, and preview what they commit to, before anything is signed.
#[derive(Debug, Parser)]
pub struct PrepareCommand {
    /// The maker's draft terms: the same economics in decimal XCH, `30d`-style deadlines and addresses.
    #[arg(long)]
    pub draft: PathBuf,

    /// Write the resolved terms to this file, ready for `create --terms`.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// The network whose address prefix the draft's bech32m parties must carry.
    #[arg(long, value_enum, default_value = "mainnet")]
    pub network: Network,

    /// The unix second a relative deadline such as `30d` is measured from. Defaults to the system clock.
    #[arg(long)]
    pub now: Option<u64>,

    /// The quote book to warn from. `prepare` never writes it.
    #[arg(long, default_value = "quotes.json")]
    pub book: PathBuf,

    /// Emit a JSON preview instead of the human lines.
    #[arg(long)]
    pub json: bool,
}

/// Precompute a quote and emit the unsigned maker spend bundle for a signer.
#[derive(Debug, Parser)]
pub struct CreateCommand {
    /// The maker's terms, as a JSON document.
    #[arg(long)]
    pub terms: PathBuf,

    /// Write the emitted document to this file as well as to stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// The network whose aggregated-signature constants the required signatures use.
    #[arg(long, value_enum, default_value = "mainnet")]
    pub network: Network,

    /// The quote book to book the backing coin in.
    #[arg(long, default_value = "quotes.json")]
    pub book: PathBuf,
}

/// Bind an externally produced signature into a landable offer plus its sidecar.
#[derive(Debug, Parser)]
pub struct SealCommand {
    /// The maker's terms, as a JSON document: the same file `create` was given.
    #[arg(long)]
    pub terms: PathBuf,

    /// The signed spend bundle: the JSON an external signer writes, or any bundle document.
    #[arg(long)]
    pub signed: PathBuf,

    /// The stem the artifacts are named after: `<stem>.offer|.json` and `<stem>-sidecar.json`.
    #[arg(long, default_value = "quote")]
    pub output: String,

    /// The offer encoding to write.
    #[arg(long, value_enum, default_value = "offer")]
    pub format: Format,

    /// The quote book to record the offer in.
    #[arg(long, default_value = "quotes.json")]
    pub book: PathBuf,

    /// Emit a JSON status document instead of a human line.
    #[arg(long)]
    pub json: bool,
}

/// Check a published offer against the terms it claims to encode.
#[derive(Debug, Parser)]
pub struct VerifyCommand {
    /// The offer file: a bech32 `.offer` or its JSON form.
    pub offer: PathBuf,

    /// The sidecar that travels with the offer, or bare terms.
    pub sidecar: PathBuf,

    /// The network whose address prefix the premium recipient is rendered with.
    #[arg(long, value_enum, default_value = "mainnet")]
    pub network: Network,

    /// Emit a JSON report instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

/// Show every booked quote.
#[derive(Debug, Parser)]
pub struct ListCommand {
    /// The quote book to read.
    #[arg(long, default_value = "quotes.json")]
    pub book: PathBuf,

    /// Emit the book as JSON instead of one line per quote.
    #[arg(long)]
    pub json: bool,
}

/// Replace a booked quote with new terms over the same backing coin.
#[derive(Debug, Parser)]
pub struct RequoteCommand {
    /// The new terms, as a JSON document.
    #[arg(long)]
    pub terms: PathBuf,

    /// Write the emitted document to this file as well as to stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// The network whose aggregated-signature constants the required signatures use.
    #[arg(long, value_enum, default_value = "mainnet")]
    pub network: Network,

    /// The quote book holding the superseded quote.
    #[arg(long, default_value = "quotes.json")]
    pub book: PathBuf,
}

/// Stop advertising a quote locally.
#[derive(Debug, Parser)]
pub struct RetireCommand {
    /// The hex id of the backing coin to retire.
    pub backing_coin_id: String,

    /// The quote book to remove the entry from.
    #[arg(long, default_value = "quotes.json")]
    pub book: PathBuf,

    /// Emit a JSON status document instead of a human line.
    #[arg(long)]
    pub json: bool,
}

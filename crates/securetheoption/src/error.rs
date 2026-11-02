//! The crate's error type.

use chia_wallet_sdk::prelude::DriverError;
use chia_wallet_sdk::signer::SignerError;

/// Everything that can go wrong while preparing, sealing or checking a quote.
#[derive(Debug, thiserror::Error)]
pub enum SecError {
    /// A filesystem operation failed.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path that was being read or written.
        path: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// A JSON document could not be read or written.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A hex field did not decode, or decoded to the wrong length.
    #[error("invalid hex in `{field}`: {message}")]
    Hex {
        /// The terms field that failed.
        field: &'static str,
        /// What was wrong with it.
        message: String,
    },

    /// The terms are internally inconsistent.
    #[error("invalid terms: {0}")]
    InvalidTerms(String),

    /// The strike asset is not XCH or a non-revocable CAT.
    #[error("unsupported strike `{0}`: only `xch` and `cat` strikes are supported")]
    UnsupportedStrike(String),

    /// A revocable CAT backing coin was supplied.
    #[error("revocable CAT backing coins are not supported: supply `hidden_puzzle_hash: null`")]
    UnsupportedRevocableCat,

    /// The SDK rejected a primitive.
    #[error("driver error: {0}")]
    Driver(#[from] DriverError),

    /// The signer rejected a spend.
    #[error("signer error: {0}")]
    Signer(#[from] SignerError),

    /// The signed bundle handed to `seal` is not the bundle the terms describe.
    #[error("the signed spend bundle does not match the terms: {0}")]
    SealedBundleMismatch(String),

    /// The bundle handed to `seal` still carries the identity signature.
    #[error("the spend bundle is unsigned: it still carries the identity signature")]
    UnsignedBundle,

    /// The parsed offer does not offer the quoted option.
    #[error("the offer does not offer the quoted option (launcher {0})")]
    OfferMissingOption(String),

    /// Verification found one or more mismatches.
    #[error("verification failed:\n{}", .0.join("\n"))]
    Verification(Vec<String>),

    /// The backing coin already has a live quote.
    #[error("coin {coin_id} already has a live quote ({offer})")]
    CoinAlreadyQuoted {
        /// The backing coin id, hex encoded.
        coin_id: String,
        /// The offer file the live quote points at.
        offer: String,
    },

    /// The quote book has no entry for the coin.
    #[error("no quote for backing coin {0}")]
    UnknownQuotedCoin(String),
}

impl SecError {
    /// Builds a [`SecError::Hex`].
    pub fn hex(field: &'static str, message: impl Into<String>) -> Self {
        Self::Hex {
            field,
            message: message.into(),
        }
    }

    /// Builds a [`SecError::InvalidTerms`].
    pub fn terms(message: impl Into<String>) -> Self {
        Self::InvalidTerms(message.into())
    }

    /// Builds a [`SecError::Io`], capturing the path for the message.
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

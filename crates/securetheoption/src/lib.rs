//! Presigned option-mint offers for Chia.
//!
//! A maker commits a backing coin by presigning the spends that would mint an option contract and lock
//! its underlying, then publishes those spends as an ordinary Chia offer. Nothing happens on chain
//! until a taker accepts, at which point the option, the underlying lock and the premium payment all
//! settle atomically. Because the terms live only in the unbroadcast bundle, re-pricing is a re-sign.
//!
//! The crate's own code is offline end to end: quote creation, offer sealing and verification never
//! open a socket, and signing is delegated to an external signer.

pub mod book;
pub mod build;
pub mod draft;
pub mod error;
pub mod offer;
pub mod quote;
pub mod resolve;
pub mod terms;
pub mod verify;

pub use book::{QuoteArtifacts, QuoteBook, QuoteEntry, QuoteStatus, SupersededQuote};
pub use build::build_maker_bundle;
pub use draft::{
    Moment, Party, PremiumDraft, StrikeDraft, TermsDraft, UnderlyingDraft, XchAmount, rfc3339,
};
pub use error::SecError;
pub use offer::{
    DerivedIds, OfferFormat, QuoteSidecar, SealedOffer, SidecarSource, artifact_file_names, seal,
    spend_bundle_from_json, spend_bundle_from_json_str, spend_bundle_json,
};
pub use quote::Quote;
pub use resolve::{ResolveContext, resolve};
pub use terms::{
    BackingAsset, BackingCat, BackingCatJson, CoinJson, Hex, LAUNCHER_AMOUNT, LineageProofJson,
    Premium, PremiumAsset, QuoteTerms, SINGLETON_AMOUNT, StrikeType,
};
pub use verify::{ModeledConditions, UnmodeledCondition, VerifyReport, verify};

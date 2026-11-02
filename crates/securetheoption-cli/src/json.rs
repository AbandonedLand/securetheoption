//! The JSON shapes the CLI emits and reads.
//!
//! The bundle codec itself is reused from the library rather than re-implemented: it is the exact
//! document an external signer reads and writes, and `chia-sdk-cli`'s version of it is private to that
//! crate. Only the pieces the library has no use for — the required-signature material and the derived
//! id summary — live here.

use anyhow::{Context, Result};
use chia_wallet_sdk::driver::decode_offer;
use chia_wallet_sdk::prelude::*;
use securetheoption::{
    DerivedIds, OfferFormat, Quote, QuoteSidecar, spend_bundle_from_json, spend_bundle_json,
};
use serde_json::{Value, json};

use crate::args::Network;

/// `0x`-prefixed lowercase hex, the form every id and program takes on the wire.
///
/// Re-exported from the library's `offer` module rather than re-implemented: the sidecar and the CLI
/// write the same ids, so the project carries one `hex_bytes`, not two copies of one format string.
/// The `pub use` keeps `crate::json::hex_bytes` resolving for `commands.rs`.
pub use securetheoption::offer::hex_bytes;

/// The unsigned bundle document `create` and `requote` emit.
///
/// The shape is `chia-sdk-cli`'s (`cancel_option.rs:122-127`): the maker's bundle under `spend_bundle`,
/// next to what a signer needs in order to sign it. `sage_sign.py` reads `spend_bundle` out of this
/// document and writes the bare bundle back, so both halves of that round trip are covered by
/// [`spend_bundle_from_text`].
pub fn unsigned_document(quote: &Quote, bundle: &SpendBundle, network: Network) -> Result<Value> {
    Ok(json!({
        "spend_bundle": spend_bundle_json(bundle),
        "required_signatures": required_signatures_json(&bundle.coin_spends, network)?,
        "terms": serde_json::to_value(&quote.terms)?,
        "derived": derived_ids(quote)?,
    }))
}

/// The identifiers a quote derives, in their on-the-wire form.
///
/// Taken from [`QuoteSidecar`] rather than re-listed here, so the CLI's summary and the sidecar a taker
/// verifies against cannot drift apart. The format argument only fills the sidecar's `format` field,
/// which none of the ids depend on.
pub fn derived_ids(quote: &Quote) -> Result<DerivedIds> {
    Ok(QuoteSidecar::from_quote(quote, OfferFormat::Offer)?.derived)
}

/// Reads a spend bundle from text: a bech32 `offer1…`, a bundle document, or a document that nests the
/// bundle under `spend_bundle`.
pub fn spend_bundle_from_text(text: &str) -> Result<SpendBundle> {
    let trimmed = text.trim();

    if trimmed.starts_with("offer1") {
        return Ok(decode_offer(trimmed)?);
    }

    let value: Value =
        serde_json::from_str(trimmed).context("failed to parse the spend bundle as JSON")?;

    // `create` emits the bundle under `spend_bundle` while an external signer writes it back bare:
    // accepting both means neither half of the round trip needs hand editing.
    let document = value.get("spend_bundle").unwrap_or(&value);

    Ok(spend_bundle_from_json(document)?)
}

/// The signatures the bundle requires, so a signer knows exactly what to produce.
pub fn required_signatures_json(coin_spends: &[CoinSpend], network: Network) -> Result<Value> {
    let mut allocator = Allocator::new();

    let required = RequiredSignature::from_coin_spends(
        &mut allocator,
        coin_spends,
        &network.agg_sig_constants(),
    )
    .context("failed to calculate the signatures the spend bundle requires")?;

    Ok(Value::Array(
        required.into_iter().map(required_signature_json).collect(),
    ))
}

/// One required signature, rendered the way `chia-sdk-cli` renders it.
fn required_signature_json(signature: RequiredSignature) -> Value {
    match signature {
        RequiredSignature::Bls(bls) => json!({
            "kind": "bls",
            "public_key": hex_bytes(bls.public_key.to_bytes()),
            // The full message to sign: the raw message followed by its domain separation data.
            "message": hex_bytes(bls.message()),
        }),
        RequiredSignature::Secp(secp) => {
            let (kind, public_key) = match secp.public_key {
                SecpPublicKey::K1(public_key) => ("k1", public_key.to_bytes()),
                SecpPublicKey::R1(public_key) => ("r1", public_key.to_bytes()),
            };

            json!({
                "kind": kind,
                "public_key": hex_bytes(public_key),
                // secp signatures sign this hash directly instead of a message.
                "message_hash": hex_bytes(secp.message_hash),
            })
        }
    }
}

/// The strike of an option, as the launcher metadata commits to it.
pub fn strike_json(strike: &OptionType) -> Value {
    match strike {
        OptionType::Xch { amount } => json!({
            "type": "xch",
            "amount": amount,
        }),
        OptionType::Cat { asset_id, amount } => json!({
            "type": "cat",
            "asset_id": hex_bytes(asset_id.to_bytes()),
            "amount": amount,
        }),
        OptionType::RevocableCat {
            asset_id,
            hidden_puzzle_hash,
            amount,
        } => json!({
            "type": "revocable_cat",
            "asset_id": hex_bytes(asset_id.to_bytes()),
            "hidden_puzzle_hash": hex_bytes(hidden_puzzle_hash.to_bytes()),
            "amount": amount,
        }),
        OptionType::Nft {
            launcher_id,
            settlement_puzzle_hash,
            amount,
        } => json!({
            "type": "nft",
            "launcher_id": hex_bytes(launcher_id.to_bytes()),
            "settlement_puzzle_hash": hex_bytes(settlement_puzzle_hash.to_bytes()),
            "amount": amount,
        }),
    }
}

#[cfg(test)]
mod tests {
    use chia_wallet_sdk::chia::bls::sign;
    use securetheoption::{
        BackingAsset, CoinJson, Hex, Premium, PremiumAsset, QuoteTerms, StrikeType,
        build_maker_bundle, seal as seal_offer,
    };

    use super::*;

    /// A single XCH-backed quote over the maker's own coin, enough to exercise every document shape.
    fn terms() -> QuoteTerms {
        let public_key = SecretKey::from_seed(&[7; 32]).public_key();
        let maker_puzzle_hash: Bytes32 = StandardLayer::new(public_key).tree_hash().into();

        QuoteTerms {
            maker_public_key: Hex::new(hex_bytes(public_key.to_bytes())),
            creator_puzzle_hash: Hex::new(hex_bytes([9; 32])),
            underlying: BackingAsset::Xch {
                coin: CoinJson {
                    parent_coin_info: Hex::new(hex_bytes([1; 32])),
                    puzzle_hash: Hex::new(hex_bytes(maker_puzzle_hash.to_bytes())),
                    amount: 1_000,
                },
            },
            underlying_amount: 500,
            strike: StrikeType::Xch { amount: 2_500 },
            expiry_seconds: 1_700_000_000,
            take_by_seconds: 1_710_000_000,
            premium: Premium {
                recipient_puzzle_hash: Hex::new(hex_bytes([11; 32])),
                amount: 25,
                asset: PremiumAsset::Xch,
            },
            launcher_coin: None,
            fee_floor: 0,
        }
    }

    /// The bundle an external signer would return: the maker's spends carrying a real signature.
    fn signed(bundle: &SpendBundle) -> SpendBundle {
        let mut signed = bundle.clone();
        signed.aggregated_signature =
            sign(&SecretKey::from_seed(&[7; 32]), b"securetheoption cli fixture");

        signed
    }

    #[test]
    fn the_unsigned_document_carries_what_a_signer_needs() -> anyhow::Result<()> {
        let quote = Quote::new(terms())?;
        let bundle = build_maker_bundle(&quote)?;
        let document = unsigned_document(&quote, &bundle, Network::Mainnet)?;

        for key in ["spend_bundle", "required_signatures", "terms", "derived"] {
            assert!(
                document.get(key).is_some(),
                "the document must carry `{key}`"
            );
        }

        // The maker's backing coin is a standard p2 spend, so it needs exactly one signature, and the
        // material names the key the terms name.
        let required = document["required_signatures"]
            .as_array()
            .expect("required signatures must be an array");
        assert_eq!(required.len(), 1);
        assert_eq!(
            required[0]["public_key"].as_str(),
            Some(hex_bytes(SecretKey::from_seed(&[7; 32]).public_key().to_bytes()).as_str())
        );

        // The derived ids are the sidecar's, so the summary cannot drift from what `verify` compares.
        assert_eq!(
            document["derived"]["launcher_id"].as_str(),
            Some(hex_bytes(quote.launcher_id.to_bytes()).as_str())
        );
        assert_eq!(
            document["derived"]["premium_nonce"].as_str(),
            Some(hex_bytes(quote.nonce.to_bytes()).as_str())
        );

        Ok(())
    }

    #[test]
    fn every_bundle_document_shape_is_read_back() -> anyhow::Result<()> {
        let quote = Quote::new(terms())?;
        let bundle = build_maker_bundle(&quote)?;

        // The shape `create` emits and an external signer consumes.
        let wrapped = serde_json::to_string(&unsigned_document(&quote, &bundle, Network::Mainnet)?)?;
        assert_eq!(spend_bundle_from_text(&wrapped)?, bundle);

        // The shape the signer writes back: the bare bundle.
        let bare = serde_json::to_string(&spend_bundle_json(&signed(&bundle)))?;
        assert_eq!(spend_bundle_from_text(&bare)?, signed(&bundle));

        // A published offer, read back through the bech32 codec.
        let sealed = seal_offer(&quote, &signed(&bundle), OfferFormat::Offer)?;
        assert_eq!(
            spend_bundle_from_text(sealed.offer_text())?,
            sealed.spend_bundle
        );

        Ok(())
    }

    #[test]
    fn text_that_is_neither_a_bundle_nor_an_offer_is_rejected() -> anyhow::Result<()> {
        let error = spend_bundle_from_text("not a bundle").unwrap_err();
        assert!(error.to_string().contains("as JSON"), "{error}");

        Ok(())
    }
}

//! Sealing and emission: binding an external signature into an offer, and writing the artifacts.
//!
//! [`crate::build`] produces an **unsigned** bundle; the maker signs it out of process (FR8) and
//! [`seal`] turns the signed bundle into a landable offer plus the plaintext sidecar a taker verifies
//! against. Sealing re-derives the bundle from the terms first, because
//! [`Offer::from_input_spend_bundle`] is the *trusted* path: it deliberately skips the puzzle-reveal
//! check a parsed offer gets, so without the comparison a signer that returned a different bundle would
//! be sealed silently.
//!
//! The emitted bundle is not the signed one. [`Offer::to_spend_bundle`] prepends one settlement
//! placeholder spend per requested-payment branch; that placeholder is what encodes the premium
//! obligation, and for a CAT premium its curried puzzle hash is what names the settlement target.

use chia_wallet_sdk::driver::encode_offer;
use chia_wallet_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::build::build_maker_bundle;
use crate::error::SecError;
use crate::quote::Quote;
use crate::terms::{CoinJson, Hex, QuoteTerms};

/// The sidecar document version, bumped only when the shape changes incompatibly.
pub const SIDECAR_VERSION: u32 = 1;

/// How a sealed offer is encoded on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferFormat {
    /// A bech32 `offer1…` string wrapping a zlib-compressed spend bundle: what wallets import.
    #[default]
    Offer,
    /// The spend bundle as JSON, for signers and for hand inspection.
    Json,
}

impl OfferFormat {
    /// The file extension an artifact in this format is written with.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Json => "json",
        }
    }
}

/// The identifiers a quote commits to, in their on-the-wire form.
///
/// The sidecar carries them so a taker compares them against its own recompute instead of trusting the
/// offer's puzzle reveals: every entry is either a hash input or one of FR1's promises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedIds {
    /// The coin whose spend creates the launcher coin: the backing coin for XCH, the `launcher_coin`
    /// term for a CAT.
    pub launcher_parent_coin_id: Hex,
    /// The `LAUNCHER_AMOUNT`-sized coin at `SINGLETON_LAUNCHER_HASH`.
    pub launcher_coin_id: Hex,
    /// The option's identity on chain, and the strike payment's nonce.
    pub launcher_id: Hex,
    /// The coin that locks the underlying.
    pub underlying_coin_id: Hex,
    /// The underlying's p2 puzzle hash, inside any asset layer.
    pub underlying_p2_puzzle_hash: Hex,
    /// The 1-of-2 MIPS puzzle the option's metadata commits to. Derived, never supplied.
    pub underlying_delegated_puzzle_hash: Hex,
    /// The eve option coin, spent inside the presigned bundle.
    pub eve_coin_id: Hex,
    /// The eve option's inner puzzle hash: `(q . ((51 owner SINGLETON_AMOUNT (owner))))`.
    pub eve_p2_puzzle_hash: Hex,
    /// The offered option coin.
    pub option_coin_id: Hex,
    /// The option's outer puzzle hash: what a coin holding the option reveals.
    pub option_puzzle_hash: Hex,
    /// The nonce the premium payment is notarized with.
    pub premium_nonce: Hex,
    /// The hash of the notarized premium payment the maker's assertion commits to.
    pub premium_payment_hash: Hex,
}

/// The plaintext quote that travels next to an offer file.
///
/// The offer itself is opaque to a taker (a spend bundle says what it says), so the terms and the ids
/// they derive go beside it: a verifier recomputes the ids from `terms` and compares them to `derived`
/// and to the offer, which is what makes the offer checkable rather than merely readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteSidecar {
    /// [`SIDECAR_VERSION`] at the time the sidecar was written.
    pub version: u32,
    /// The encoding of the offer file this sidecar belongs to.
    pub format: OfferFormat,
    /// The maker's terms, in full.
    pub terms: QuoteTerms,
    /// What those terms derive, as the maker computed it.
    pub derived: DerivedIds,
}

impl QuoteSidecar {
    /// Captures `quote` as a sidecar for an offer in `format`.
    pub fn from_quote(quote: &Quote, format: OfferFormat) -> Result<Self, SecError> {
        Ok(Self {
            version: SIDECAR_VERSION,
            format,
            terms: quote.terms.clone(),
            derived: DerivedIds {
                launcher_parent_coin_id: hex_id(quote.launcher_parent_coin.coin_id().to_bytes()),
                launcher_coin_id: hex_id(quote.launcher_coin.coin_id().to_bytes()),
                launcher_id: hex_id(quote.launcher_id.to_bytes()),
                underlying_coin_id: hex_id(quote.underlying_coin.coin_id().to_bytes()),
                underlying_p2_puzzle_hash: hex_id(
                    quote.underlying_p2_puzzle_hash().to_bytes(),
                ),
                underlying_delegated_puzzle_hash: hex_id(
                    quote.info.underlying_delegated_puzzle_hash.to_bytes(),
                ),
                eve_coin_id: hex_id(quote.eve_coin.coin_id().to_bytes()),
                eve_p2_puzzle_hash: hex_id(quote.eve_p2_puzzle_hash.to_bytes()),
                option_coin_id: hex_id(quote.option_coin.coin_id().to_bytes()),
                option_puzzle_hash: hex_id(quote.option_puzzle_hash().to_bytes()),
                premium_nonce: hex_id(quote.nonce.to_bytes()),
                premium_payment_hash: hex_id(Bytes32::from(quote.premium_payment_hash()?).to_bytes()),
            },
        })
    }

    /// Serialises the sidecar as pretty JSON.
    pub fn to_json(&self) -> Result<String, SecError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parses a sidecar document.
    pub fn from_json(text: &str) -> Result<Self, SecError> {
        Ok(serde_json::from_str(text)?)
    }
}

/// What a verifier was handed: a full sidecar, or bare terms with nothing to compare against.
///
/// Accepting bare terms keeps the flow usable when a taker only has the maker's terms file, at the
/// cost of losing the derived-id comparison. The two shapes are distinguished by content: a sidecar
/// has `terms` and `derived`, bare terms have `underlying` and `strike`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SidecarSource {
    /// A full sidecar document.
    Sidecar(QuoteSidecar),
    /// Bare terms, with no derived ids to compare.
    Terms(QuoteTerms),
}

impl SidecarSource {
    /// The terms, whichever shape this is.
    pub fn terms(&self) -> &QuoteTerms {
        match self {
            Self::Sidecar(sidecar) => &sidecar.terms,
            Self::Terms(terms) => terms,
        }
    }

    /// The terms, consumed.
    pub fn into_terms(self) -> QuoteTerms {
        match self {
            Self::Sidecar(sidecar) => sidecar.terms,
            Self::Terms(terms) => terms,
        }
    }

    /// The derived ids, when the source carried them.
    pub fn derived(&self) -> Option<&DerivedIds> {
        match self {
            Self::Sidecar(sidecar) => Some(&sidecar.derived),
            Self::Terms(_) => None,
        }
    }
}

impl From<QuoteSidecar> for SidecarSource {
    fn from(sidecar: QuoteSidecar) -> Self {
        Self::Sidecar(sidecar)
    }
}

impl From<QuoteTerms> for SidecarSource {
    fn from(terms: QuoteTerms) -> Self {
        Self::Terms(terms)
    }
}

/// A sealed offer: the landable bundle, its encoded form, and the sidecar that explains it.
#[derive(Debug, Clone)]
pub struct SealedOffer {
    /// The encoding [`SealedOffer::offer_text`] uses.
    pub format: OfferFormat,
    /// The complete offer bundle: the maker's spends plus one settlement placeholder per
    /// requested-payment branch. This is *not* the bundle the maker signed — it is the bundle a taker
    /// completes.
    pub spend_bundle: SpendBundle,
    /// The plaintext quote the taker recomputes from.
    pub sidecar: QuoteSidecar,
    /// The encoded offer, ready for `<stem>.<ext>`.
    offer_text: String,
    /// The encoded sidecar, ready for `<stem>-sidecar.json`.
    sidecar_text: String,
}

impl SealedOffer {
    /// The encoded offer in [`SealedOffer::format`].
    pub fn offer_text(&self) -> &str {
        &self.offer_text
    }

    /// The encoded sidecar.
    pub fn sidecar_text(&self) -> &str {
        &self.sidecar_text
    }
}

/// The file names the seal artifacts are written to, given a stem.
///
/// `<stem>.offer` or `<stem>.json` for the offer, and `<stem>-sidecar.json` for the sidecar. The
/// sidecar keeps a `.json` extension in both cases so it is never mistaken for an offer.
pub fn artifact_file_names(stem: &str, format: OfferFormat) -> (String, String) {
    (
        format!("{stem}.{}", format.extension()),
        format!("{stem}-sidecar.json"),
    )
}

/// Binds a maker's out-of-process signature into a landable offer.
///
/// The signed bundle is checked against a bundle rebuilt from the terms before anything is bound: every
/// coin, puzzle reveal and solution must match, and the identity signature is refused outright. Only
/// then is the bundle handed to [`Offer::from_input_spend_bundle`], which trusts what it is given.
pub fn seal(
    quote: &Quote,
    signed: &SpendBundle,
    format: OfferFormat,
) -> Result<SealedOffer, SecError> {
    if signed.aggregated_signature == Signature::default() {
        return Err(SecError::UnsignedBundle);
    }

    let expected = build_maker_bundle(quote)?;
    check_spends_match(&expected, signed)?;

    let mut ctx = SpendContext::new();
    let requested_payments = quote.requested_payments(&mut ctx)?;
    let asset_info = quote.asset_info()?;

    let offer = Offer::from_input_spend_bundle(
        &mut ctx,
        signed.clone(),
        requested_payments,
        asset_info,
    )?;

    // An offer that does not register the option offers nothing, and would fail at take time rather
    // than here. The parser only recognises an odd-amount child whose inner p2 is the settlement
    // puzzle, so this also proves the eve spend was built the way the quote says.
    match offer.offered_coins().options.get(&quote.launcher_id) {
        Some(option) if option.coin.coin_id() == quote.option_coin.coin_id() => {}
        _ => {
            return Err(SecError::OfferMissingOption(hex_bytes(
                quote.launcher_id.to_bytes(),
            )));
        }
    }

    let spend_bundle = offer.to_spend_bundle(&mut ctx)?;

    let offer_text = match format {
        OfferFormat::Offer => encode_offer(&spend_bundle)?,
        OfferFormat::Json => serde_json::to_string_pretty(&spend_bundle_json(&spend_bundle))?,
    };

    let sidecar = QuoteSidecar::from_quote(quote, format)?;
    let sidecar_text = sidecar.to_json()?;

    Ok(SealedOffer {
        format,
        spend_bundle,
        sidecar,
        offer_text,
        sidecar_text,
    })
}

/// Requires the signed bundle to be the bundle the terms describe.
///
/// Comparison is by coin id rather than by position: Chia ignores the order of a bundle's spends, so a
/// signer that reorders them has not changed the bundle, and rejecting it would be a false alarm. What
/// is compared strictly is the content of each spend — the coin, the puzzle reveal and the solution.
fn check_spends_match(expected: &SpendBundle, signed: &SpendBundle) -> Result<(), SecError> {
    if expected.coin_spends.len() != signed.coin_spends.len() {
        return Err(SecError::SealedBundleMismatch(format!(
            "the signed bundle has {} coin spends but the terms describe {}",
            signed.coin_spends.len(),
            expected.coin_spends.len()
        )));
    }

    let mut expected_spends: Vec<&CoinSpend> = expected.coin_spends.iter().collect();
    let mut signed_spends: Vec<&CoinSpend> = signed.coin_spends.iter().collect();
    expected_spends.sort_by_key(|coin_spend| coin_spend.coin.coin_id());
    signed_spends.sort_by_key(|coin_spend| coin_spend.coin.coin_id());

    for (expected, signed) in expected_spends.iter().zip(&signed_spends) {
        if expected.coin != signed.coin {
            return Err(SecError::SealedBundleMismatch(format!(
                "the signed bundle spends coin {} where the terms describe coin {}",
                signed.coin.coin_id(),
                expected.coin.coin_id()
            )));
        }

        if expected.puzzle_reveal.to_vec() != signed.puzzle_reveal.to_vec() {
            return Err(SecError::SealedBundleMismatch(format!(
                "the puzzle reveal of coin {} is not the puzzle the terms describe",
                signed.coin.coin_id()
            )));
        }

        if expected.solution.to_vec() != signed.solution.to_vec() {
            return Err(SecError::SealedBundleMismatch(format!(
                "the solution of coin {} is not the solution the terms describe",
                signed.coin.coin_id()
            )));
        }
    }

    Ok(())
}

/// The bundle JSON document: `{ coin_spends: [...], aggregated_signature: 0x… }`.
///
/// `chia_protocol::SpendBundle` has no serde impl, so the shape is hand-written — deliberately the same
/// one `chia-sdk-cli` emits, so a bundle this tool writes and a bundle it reads are the ones an
/// external signer already handles.
pub fn spend_bundle_json(spend_bundle: &SpendBundle) -> serde_json::Value {
    serde_json::json!({
        "coin_spends": spend_bundle
            .coin_spends
            .iter()
            .map(coin_spend_json)
            .collect::<Vec<_>>(),
        "aggregated_signature": hex_bytes(spend_bundle.aggregated_signature.to_bytes()),
    })
}

/// One spend in the bundle JSON document.
pub fn coin_spend_json(coin_spend: &CoinSpend) -> serde_json::Value {
    serde_json::json!({
        "coin": {
            "amount": coin_spend.coin.amount,
            "parent_coin_info": hex_bytes(coin_spend.coin.parent_coin_info.to_bytes()),
            "puzzle_hash": hex_bytes(coin_spend.coin.puzzle_hash.to_bytes()),
        },
        "puzzle_reveal": hex_bytes(coin_spend.puzzle_reveal.to_vec()),
        "solution": hex_bytes(coin_spend.solution.to_vec()),
    })
}

/// Parses a bundle JSON document, as an offer file may carry one.
pub fn spend_bundle_from_json(value: &serde_json::Value) -> Result<SpendBundle, SecError> {
    let document: SpendBundleDocument = serde_json::from_value(value.clone())?;
    let mut coin_spends = Vec::with_capacity(document.coin_spends.len());

    for (index, coin_spend) in document.coin_spends.iter().enumerate() {
        coin_spends.push(CoinSpend::new(
            coin_spend.coin.coin()?,
            Program::from(hex_blob(&coin_spend.puzzle_reveal, "puzzle_reveal", index)?),
            Program::from(hex_blob(&coin_spend.solution, "solution", index)?),
        ));
    }

    let signature_bytes = document
        .aggregated_signature
        .bytes::<96>("aggregated_signature")?;

    let aggregated_signature = Signature::from_bytes(&signature_bytes)
        .map_err(|error| SecError::hex("aggregated_signature", error.to_string()))?;

    Ok(SpendBundle::new(coin_spends, aggregated_signature))
}

/// Parses a bundle JSON document from text.
pub fn spend_bundle_from_json_str(text: &str) -> Result<SpendBundle, SecError> {
    spend_bundle_from_json(&serde_json::from_str(text)?)
}

/// `0x`-prefixed lowercase hex, the form every id and program takes on the wire.
pub fn hex_bytes(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// A [`Hex`] id in the wire form every derived id takes.
fn hex_id(bytes: impl AsRef<[u8]>) -> Hex {
    Hex(hex_bytes(bytes))
}

/// Decodes one program-sized field of the bundle document.
fn hex_blob(hex: &Hex, field: &'static str, index: usize) -> Result<Vec<u8>, SecError> {
    let trimmed = hex
        .0
        .strip_prefix("0x")
        .or_else(|| hex.0.strip_prefix("0X"))
        .unwrap_or(hex.0.as_str());

    hex::decode(trimmed)
        .map_err(|error| SecError::hex(field, format!("coin_spends[{index}]: {error}")))
}

/// The bundle document, as written and as read back.
#[derive(Debug, Deserialize)]
struct SpendBundleDocument {
    coin_spends: Vec<CoinSpendDocument>,
    aggregated_signature: Hex,
}

/// One spend of the bundle document.
#[derive(Debug, Deserialize)]
struct CoinSpendDocument {
    coin: CoinJson,
    puzzle_reveal: Hex,
    solution: Hex,
}

#[cfg(test)]
mod tests {
    use chia_wallet_sdk::chia::bls::sign;
    use chia_wallet_sdk::driver::decode_offer;
    use chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH;

    use crate::terms::{
        BackingAsset, BackingCatJson, LineageProofJson, Premium, PremiumAsset, SINGLETON_AMOUNT,
        StrikeType,
    };

    use super::*;

    fn hex32(bytes: [u8; 32]) -> Hex {
        Hex(format!("0x{}", hex::encode(bytes)))
    }

    fn maker() -> (Hex, Bytes32) {
        let secret_key = SecretKey::from_seed(&[7; 32]);
        let public_key = secret_key.public_key();
        let maker_public_key = Hex(format!("0x{}", hex::encode(public_key.to_bytes())));
        let puzzle_hash: Bytes32 = StandardLayer::new(public_key).tree_hash().into();
        (maker_public_key, puzzle_hash)
    }

    /// A real BLS signature over an unrelated message. `seal` only refuses the identity placeholder, so
    /// any non-identity signature stands in for the signer's.
    ///
    /// `chia_bls` only exposes `SecretKey::sign` behind its `py-bindings` feature, so this has to go
    /// through the free function.
    fn fixture_signature() -> Signature {
        sign(
            &SecretKey::from_seed(&[7; 32]),
            b"securetheoption seal fixture",
        )
    }

    fn premium() -> Premium {
        Premium {
            recipient_puzzle_hash: hex32([11; 32]),
            amount: 25,
            asset: PremiumAsset::Xch,
        }
    }

    fn xch_terms(backing_amount: u64) -> QuoteTerms {
        let (maker_public_key, maker_puzzle_hash) = maker();

        QuoteTerms {
            maker_public_key,
            creator_puzzle_hash: hex32([9; 32]),
            underlying: BackingAsset::Xch {
                coin: CoinJson {
                    parent_coin_info: hex32([1; 32]),
                    puzzle_hash: hex32(maker_puzzle_hash.to_bytes()),
                    amount: backing_amount,
                },
            },
            underlying_amount: 500,
            strike: StrikeType::Xch { amount: 2_500 },
            expiry_seconds: 1_700_000_000,
            take_by_seconds: 1_710_000_000,
            premium: premium(),
            launcher_coin: None,
            fee_floor: 0,
        }
    }

    /// A CAT terms fixture whose lineage proof is self-consistent, so the CAT puzzle can be run.
    fn cat_terms() -> QuoteTerms {
        let (maker_public_key, maker_puzzle_hash) = maker();
        let asset_id = Bytes32::new([5; 32]);

        let parent_parent_coin_info = Bytes32::new([2; 32]);
        let parent_inner_puzzle_hash = Bytes32::new([3; 32]);
        let parent_amount = 5_000;
        let parent_puzzle_hash: Bytes32 =
            CatInfo::new(asset_id, None, parent_inner_puzzle_hash)
                .puzzle_hash()
                .into();
        let parent_coin_id =
            Coin::new(parent_parent_coin_info, parent_puzzle_hash, parent_amount).coin_id();

        let backing_puzzle_hash: Bytes32 = CatInfo::new(asset_id, None, maker_puzzle_hash)
            .puzzle_hash()
            .into();

        QuoteTerms {
            maker_public_key,
            creator_puzzle_hash: hex32([9; 32]),
            underlying: BackingAsset::Cat {
                coin: CoinJson {
                    parent_coin_info: hex32(parent_coin_id.to_bytes()),
                    puzzle_hash: hex32(backing_puzzle_hash.to_bytes()),
                    amount: 1_000,
                },
                backing_cat: BackingCatJson {
                    asset_id: hex32(asset_id.to_bytes()),
                    hidden_puzzle_hash: None,
                    lineage_proof: LineageProofJson {
                        parent_parent_coin_info: hex32(parent_parent_coin_info.to_bytes()),
                        parent_inner_puzzle_hash: hex32(parent_inner_puzzle_hash.to_bytes()),
                        parent_amount,
                    },
                },
            },
            underlying_amount: 1_000,
            strike: StrikeType::Xch { amount: 2_500 },
            expiry_seconds: 1_700_000_000,
            take_by_seconds: 1_710_000_000,
            premium: premium(),
            launcher_coin: Some(CoinJson {
                parent_coin_info: hex32([4; 32]),
                puzzle_hash: hex32(maker_puzzle_hash.to_bytes()),
                amount: SINGLETON_AMOUNT,
            }),
            fee_floor: 0,
        }
    }

    /// CAT backing with a CAT premium in an unrelated asset.
    fn cat_premium_terms(hidden_puzzle_hash: Option<[u8; 32]>) -> QuoteTerms {
        let mut terms = cat_terms();

        terms.premium.asset = PremiumAsset::Cat {
            asset_id: hex32([13; 32]),
            hidden_puzzle_hash: hidden_puzzle_hash.map(hex32),
        };

        terms
    }

    /// The bundle a signer would return: the maker's spends carrying a real signature.
    fn signed(quote: &Quote) -> Result<SpendBundle, SecError> {
        let mut spend_bundle = build_maker_bundle(quote)?;
        spend_bundle.aggregated_signature = fixture_signature();
        Ok(spend_bundle)
    }

    #[test]
    fn seal_refuses_the_identity_signature() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let unsigned = build_maker_bundle(&quote)?;

        assert!(matches!(
            seal(&quote, &unsigned, OfferFormat::Offer),
            Err(SecError::UnsignedBundle)
        ));

        Ok(())
    }

    #[test]
    fn seal_refuses_a_bundle_with_a_different_solution() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let mut tampered = signed(&quote)?;
        tampered.coin_spends[0].solution = Program::from(vec![0x80]);

        let error = seal(&quote, &tampered, OfferFormat::Offer).unwrap_err();
        assert!(matches!(error, SecError::SealedBundleMismatch(_)), "{error}");
        assert!(error.to_string().contains("solution"), "{error}");

        Ok(())
    }

    #[test]
    fn seal_refuses_a_bundle_with_a_foreign_coin() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let mut tampered = signed(&quote)?;
        tampered.coin_spends[0].coin =
            Coin::new(Bytes32::new([42; 32]), Bytes32::new([42; 32]), 7);

        let error = seal(&quote, &tampered, OfferFormat::Offer).unwrap_err();
        assert!(matches!(error, SecError::SealedBundleMismatch(_)), "{error}");
        assert!(error.to_string().contains("spends coin"), "{error}");

        Ok(())
    }

    #[test]
    fn seal_refuses_a_bundle_with_a_spend_missing() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let mut tampered = signed(&quote)?;
        tampered.coin_spends.pop();

        let error = seal(&quote, &tampered, OfferFormat::Offer).unwrap_err();
        assert!(matches!(error, SecError::SealedBundleMismatch(_)), "{error}");
        assert!(error.to_string().contains("coin spends"), "{error}");

        Ok(())
    }

    #[test]
    fn seal_carries_the_signed_spends_and_adds_one_settlement_placeholder() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let signed = signed(&quote)?;
        let sealed = seal(&quote, &signed, OfferFormat::Offer)?;

        assert_eq!(sealed.spend_bundle.coin_spends.len(), 4);
        assert_eq!(
            sealed.spend_bundle.aggregated_signature,
            fixture_signature()
        );

        // The maker's spends are carried byte for byte; the placeholder is prepended, and it is the
        // only spend with a zero parent coin id.
        let placeholder = &sealed.spend_bundle.coin_spends[0];
        assert_eq!(placeholder.coin.parent_coin_info, Bytes32::default());
        assert_eq!(placeholder.coin.amount, 0);
        assert_eq!(placeholder.coin.puzzle_hash, SETTLEMENT_PAYMENT_HASH.into());

        for coin_spend in &signed.coin_spends {
            let carried = sealed
                .spend_bundle
                .coin_spends
                .iter()
                .find(|carried| carried.coin == coin_spend.coin)
                .expect("the maker's spend is carried into the offer");

            assert_eq!(
                carried.puzzle_reveal.to_vec(),
                coin_spend.puzzle_reveal.to_vec()
            );
            assert_eq!(carried.solution.to_vec(), coin_spend.solution.to_vec());
        }

        Ok(())
    }

    #[test]
    fn a_cat_premium_placeholder_targets_the_cat_settlement_puzzle() -> anyhow::Result<()> {
        let quote = Quote::new(cat_premium_terms(Some([6; 32])))?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Offer)?;

        let placeholder = &sealed.spend_bundle.coin_spends[0];
        assert_eq!(placeholder.coin.parent_coin_info, Bytes32::default());
        assert_eq!(
            placeholder.coin.puzzle_hash,
            quote.premium_settlement_puzzle_hash()?
        );

        // A revocable CAT premium settles somewhere else entirely, which is why the hidden hash is a
        // term rather than something the tool infers.
        assert_ne!(placeholder.coin.puzzle_hash, SETTLEMENT_PAYMENT_HASH.into());

        Ok(())
    }

    #[test]
    fn a_cat_backed_quote_keeps_its_four_maker_spends() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let signed = signed(&quote)?;
        let sealed = seal(&quote, &signed, OfferFormat::Offer)?;

        assert_eq!(signed.coin_spends.len(), 4);
        assert_eq!(sealed.spend_bundle.coin_spends.len(), 5);
        assert_eq!(
            sealed
                .spend_bundle
                .coin_spends
                .iter()
                .filter(|coin_spend| coin_spend.coin.parent_coin_info != Bytes32::default())
                .count(),
            4
        );

        Ok(())
    }

    #[test]
    fn the_offer_text_decodes_back_to_the_sealed_bundle() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Offer)?;

        assert_eq!(decode_offer(sealed.offer_text())?, sealed.spend_bundle);

        Ok(())
    }

    #[test]
    fn the_json_format_round_trips_through_the_bundle_codec() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Json)?;

        assert_eq!(sealed.format, OfferFormat::Json);
        assert!(sealed.offer_text().starts_with('{'));

        let value: serde_json::Value = serde_json::from_str(sealed.offer_text())?;
        assert_eq!(spend_bundle_from_json(&value)?, sealed.spend_bundle);
        assert_eq!(
            spend_bundle_from_json_str(sealed.offer_text())?,
            sealed.spend_bundle
        );

        Ok(())
    }

    #[test]
    fn the_sealed_offer_survives_an_untrusted_parse() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Offer)?;

        let mut allocator = Allocator::new();
        let spend_bundle = decode_offer(sealed.offer_text())?;
        let offer = Offer::from_spend_bundle(&mut allocator, &spend_bundle)?;

        let option = offer
            .offered_coins()
            .options
            .get(&quote.launcher_id)
            .expect("the offer offers the quoted option");
        assert_eq!(option.coin, quote.option_coin);
        assert_eq!(option.info, quote.info);

        let requested = offer.requested_payments();
        assert_eq!(requested.xch.len(), 1);

        let payment = &requested.xch[0];
        assert_eq!(payment.nonce, quote.nonce);
        assert_eq!(payment.payments.len(), 1);
        assert_eq!(payment.payments[0].amount, quote.terms.premium.amount);
        assert_eq!(
            payment.payments[0].puzzle_hash,
            quote.terms.premium_recipient()?
        );

        // `Offer::from_spend_bundle` strips the parent-zero placeholders into `requested_payments`, so
        // the parsed offer's bundle is the maker's half alone: it removes exactly what it creates, and
        // the premium shows up as a request rather than as a hole in `fee()`.
        assert_eq!(offer.fee()?, 0);
        assert_eq!(requested.xch[0].payments[0].amount, quote.terms.premium.amount);

        Ok(())
    }

    #[test]
    fn the_sidecar_records_every_derived_id() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Offer)?;
        let derived = &sealed.sidecar.derived;

        assert_eq!(sealed.sidecar.version, SIDECAR_VERSION);
        assert_eq!(sealed.sidecar.format, OfferFormat::Offer);
        assert_eq!(sealed.sidecar.terms, quote.terms);

        assert_eq!(
            derived.launcher_parent_coin_id,
            hex_id(quote.launcher_parent_coin.coin_id().to_bytes())
        );
        assert_eq!(
            derived.launcher_coin_id,
            hex_id(quote.launcher_coin.coin_id().to_bytes())
        );
        assert_eq!(derived.launcher_id, hex_id(quote.launcher_id.to_bytes()));
        assert_eq!(
            derived.underlying_coin_id,
            hex_id(quote.underlying_coin.coin_id().to_bytes())
        );
        assert_eq!(
            derived.underlying_p2_puzzle_hash,
            hex_id(quote.underlying_p2_puzzle_hash().to_bytes())
        );
        assert_eq!(
            derived.underlying_delegated_puzzle_hash,
            hex_id(quote.info.underlying_delegated_puzzle_hash.to_bytes())
        );
        assert_eq!(
            derived.eve_coin_id,
            hex_id(quote.eve_coin.coin_id().to_bytes())
        );
        assert_eq!(
            derived.eve_p2_puzzle_hash,
            hex_id(quote.eve_p2_puzzle_hash.to_bytes())
        );
        assert_eq!(
            derived.option_coin_id,
            hex_id(quote.option_coin.coin_id().to_bytes())
        );
        assert_eq!(
            derived.option_puzzle_hash,
            hex_id(quote.option_puzzle_hash().to_bytes())
        );
        assert_eq!(derived.premium_nonce, hex_id(quote.nonce.to_bytes()));
        assert_eq!(
            derived.premium_payment_hash,
            hex_id(Bytes32::from(quote.premium_payment_hash()?).to_bytes())
        );

        Ok(())
    }

    #[test]
    fn the_sidecar_round_trips_through_json() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Offer)?;

        assert_eq!(QuoteSidecar::from_json(sealed.sidecar_text())?, sealed.sidecar);

        Ok(())
    }

    #[test]
    fn the_sidecar_source_accepts_both_documents() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Offer)?;

        let full: SidecarSource = serde_json::from_str(sealed.sidecar_text())?;
        assert!(matches!(full, SidecarSource::Sidecar(_)));
        assert_eq!(full.terms(), &quote.terms);
        assert_eq!(full.derived(), Some(&sealed.sidecar.derived));

        let bare: SidecarSource = serde_json::from_str(&serde_json::to_string(&quote.terms)?)?;
        assert!(matches!(bare, SidecarSource::Terms(_)));
        assert_eq!(bare.terms(), &quote.terms);
        assert_eq!(bare.derived(), None);
        assert_eq!(bare.into_terms(), quote.terms);

        Ok(())
    }

    #[test]
    fn sealing_the_same_bundle_twice_matches() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let signed = signed(&quote)?;

        let first = seal(&quote, &signed, OfferFormat::Offer)?;
        let second = seal(&quote, &signed, OfferFormat::Offer)?;

        assert_eq!(first.offer_text(), second.offer_text());
        assert_eq!(first.sidecar_text(), second.sidecar_text());
        assert_eq!(first.spend_bundle, second.spend_bundle);

        Ok(())
    }

    #[test]
    fn artifact_names_follow_the_format() -> anyhow::Result<()> {
        assert_eq!(
            artifact_file_names("acme", OfferFormat::Offer),
            ("acme.offer".to_string(), "acme-sidecar.json".to_string())
        );
        assert_eq!(
            artifact_file_names("acme", OfferFormat::Json),
            ("acme.json".to_string(), "acme-sidecar.json".to_string())
        );

        Ok(())
    }

    #[test]
    fn the_bundle_codec_names_its_fields() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = seal(&quote, &signed(&quote)?, OfferFormat::Json)?;

        // A document missing `coin_spends` is a JSON shape error, not an empty bundle.
        let error = spend_bundle_from_json_str("{}").unwrap_err();
        assert!(matches!(error, SecError::Json(_)), "{error}");
        assert!(error.to_string().contains("coin_spends"), "{error}");

        let mut value = spend_bundle_json(&sealed.spend_bundle);
        value["coin_spends"][0]["puzzle_reveal"] = serde_json::json!("0xzz");

        let error = spend_bundle_from_json(&value).unwrap_err();
        assert!(matches!(error, SecError::Hex { .. }), "{error}");
        assert!(error.to_string().contains("puzzle_reveal"), "{error}");

        Ok(())
    }
    #[test]
    fn a_premium_cat_colliding_with_the_backing_cat_is_rejected() -> anyhow::Result<()> {
        // `AssetInfo::insert_cat` refuses one asset id carrying two different `hidden_puzzle_hash`
        // values. The premium's CAT is inserted from the terms, and `OfferCoins::parse` inserts one
        // for every CAT child the ring creates, so naming the backing CAT's asset id here collides
        // and surfaces as an error rather than an offer nobody can parse (Verification Note 9).
        let mut terms = cat_terms();
        terms.premium.asset = PremiumAsset::Cat {
            asset_id: hex32([5; 32]),
            hidden_puzzle_hash: Some(hex32([6; 32])),
        };

        let quote = Quote::new(terms)?;
        let error = seal(&quote, &signed(&quote)?, OfferFormat::Offer).unwrap_err();

        assert!(
            matches!(error, SecError::Driver(DriverError::IncompatibleAssetInfo)),
            "{error}"
        );

        Ok(())
    }
}

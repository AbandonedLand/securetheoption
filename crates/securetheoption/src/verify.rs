//! Strict verification of a published offer against the terms it was made from.
//!
//! Everything here is offline and sidecar-driven: the sidecar's terms are re-derived from scratch and
//! the result is compared with what the offer actually commits to, so a taker never has to trust a
//! puzzle reveal or a number the maker printed. The check is strict where the terms are precise — the
//! premium and the take-by deadline must be present exactly once and must be the ones the terms name —
//! and merely reported where the tool has no model for a condition, since an unusual condition is not
//! necessarily a wrong offer.
//!
//! Nothing here checks signatures. A wrong signature is not the verifier's to find: validity is the
//! network's concern and a bad signature fails at take time, after which nothing has moved.

use chia_wallet_sdk::prelude::*;

use crate::error::SecError;
use crate::offer::{DerivedIds, QuoteSidecar, SidecarSource, hex_bytes};
use crate::quote::Quote;
use crate::terms::Hex;

/// The conditions the verifier models, as the maker's spends carry them.
///
/// Only reachable through [`verify`], which is what guarantees these are the values the terms demand:
/// each of these sets has to be a single-element set and that element has to be the corresponding
/// term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeledConditions {
    /// The `AssertBeforeSecondsAbsolute` deadline: the offer cannot land after this second.
    pub take_by: u64,
    /// The announcement id of the `AssertPuzzleAnnouncement` that binds the offer to the premium.
    pub premium_assertion: Bytes32,
}

/// A condition the verifier does not model, reported so a taker can see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmodeledCondition {
    /// The coin whose spend carries the condition.
    pub coin_id: Bytes32,
    /// The condition, rendered as hex when it is opaque.
    pub condition: String,
}

/// Everything a verified offer was checked against.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// The quote recomputed from the sidecar's terms: every derived id, re-derived.
    pub quote: Quote,
    /// The `OptionMetadata` the launcher spend commits to, read from its solution.
    pub metadata: OptionMetadata,
    /// The notarized premium payment hash the maker's assertion commits to.
    pub premium_payment_hash: Hex,
    /// The modeled conditions, matching the terms exactly.
    pub modeled: ModeledConditions,
    /// The conditions the verifier does not model; empty for a bundle this tool produced.
    pub unmodeled_conditions: Vec<UnmodeledCondition>,
}

/// Checks a published offer against the terms it claims to encode.
///
/// `offer` is the sealed spend bundle — the maker's spends plus one settlement placeholder per
/// requested-payment branch — and `sidecar` is either the full sidecar or bare terms. The terms are
/// re-derived from scratch, so a sidecar cannot assert anything the terms do not imply, and every
/// mismatch accumulates into one [`SecError::Verification`] so a taker sees all of them at once.
pub fn verify(
    offer: &SpendBundle,
    sidecar: impl Into<SidecarSource>,
) -> Result<VerifyReport, SecError> {
    let source = sidecar.into();
    let quote = Quote::new(source.terms().clone())?;

    let mut errors = Vec::new();

    if let Some(claimed) = source.derived() {
        check_derived(&mut errors, claimed, &quote);
    }

    let mut allocator = Allocator::new();
    let parsed = Offer::from_spend_bundle(&mut allocator, offer)?;

    check_option(&mut errors, &parsed, &quote);

    let Some(launcher_spend) = offer
        .coin_spends
        .iter()
        .find(|coin_spend| coin_spend.coin.coin_id() == quote.launcher_coin.coin_id())
    else {
        errors.push(format!(
            "the offer never spends the launcher coin {}",
            quote.launcher_coin.coin_id()
        ));

        return Err(SecError::Verification(errors));
    };

    let metadata = match launcher_metadata(&mut allocator, launcher_spend) {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(format!(
                "the launcher spend of coin {} cannot be read: {error}",
                launcher_spend.coin.coin_id()
            ));

            return Err(SecError::Verification(errors));
        }
    };

    check_metadata(&mut errors, &metadata, &quote);

    // Only the maker's own spends are modelled. A settlement placeholder carries the parent coin id
    // zero and belongs to the taker's half of the trade; for a CAT premium it is not even runnable,
    // because the CAT layer would be handed a settlement solution instead of a CAT solution.
    let mut found = Found::default();

    for coin_spend in &offer.coin_spends {
        if coin_spend.coin.parent_coin_info == Bytes32::default() {
            continue;
        }

        match run_conditions(&mut allocator, coin_spend) {
            Ok(conditions) => {
                collect(
                    &allocator,
                    coin_spend.coin.coin_id(),
                    conditions,
                    &mut found,
                );
            }
            Err(error) => errors.push(format!(
                "the spend of coin {} cannot be run: {error}",
                coin_spend.coin.coin_id()
            )),
        }
    }

    let mut ctx = SpendContext::new();
    let premium_assertion = quote.premium_assertion(&mut ctx)?;

    if found.take_by != vec![quote.terms.take_by_seconds] {
        errors.push(format!(
            "the maker's spends carry `AssertBeforeSecondsAbsolute` for {} but the sidecar terms say \
             take-by {} (exactly one deadline is required)",
            describe_u64(&found.take_by),
            quote.terms.take_by_seconds
        ));
    }

    if found.premium_assertions != vec![premium_assertion.announcement_id] {
        errors.push(format!(
            "the maker's spends carry `AssertPuzzleAnnouncement` {} but the terms notarize the \
             premium as {} (exactly one assertion is required)",
            describe_bytes32(&found.premium_assertions),
            premium_assertion.announcement_id
        ));
    }

    if !errors.is_empty() {
        return Err(SecError::Verification(errors));
    }

    let premium_payment_hash = Hex(hex_bytes(
        Bytes32::from(quote.premium_payment_hash()?).to_bytes(),
    ));

    Ok(VerifyReport {
        metadata,
        premium_payment_hash,
        modeled: ModeledConditions {
            take_by: quote.terms.take_by_seconds,
            premium_assertion: premium_assertion.announcement_id,
        },
        unmodeled_conditions: found.unmodeled,
        quote,
    })
}

/// What the maker's spends carry, before the terms are compared against it.
#[derive(Debug, Default)]
struct Found {
    /// Every `AssertBeforeSecondsAbsolute` deadline found, in bundle order.
    take_by: Vec<u64>,
    /// Every `AssertPuzzleAnnouncement` announcement id found, in bundle order.
    premium_assertions: Vec<Bytes32>,
    /// Every condition the verifier has no model for.
    unmodeled: Vec<UnmodeledCondition>,
}

/// Compares every id the sidecar claims against the one the terms derive.
///
/// The sidecar exists so a taker can compare its own recompute instead of trusting the offer's
/// reveals, which only works if the claims are checked rather than read.
fn check_derived(
    errors: &mut Vec<String>,
    claimed: &DerivedIds,
    quote: &Quote,
) {
    check_id(
        errors,
        "launcher_parent_coin_id",
        &claimed.launcher_parent_coin_id,
        quote.launcher_parent_coin.coin_id(),
    );
    check_id(
        errors,
        "launcher_coin_id",
        &claimed.launcher_coin_id,
        quote.launcher_coin.coin_id(),
    );
    check_id(errors, "launcher_id", &claimed.launcher_id, quote.launcher_id);
    check_id(
        errors,
        "underlying_coin_id",
        &claimed.underlying_coin_id,
        quote.underlying_coin.coin_id(),
    );
    check_id(
        errors,
        "underlying_p2_puzzle_hash",
        &claimed.underlying_p2_puzzle_hash,
        quote.underlying_p2_puzzle_hash(),
    );
    check_id(
        errors,
        "underlying_delegated_puzzle_hash",
        &claimed.underlying_delegated_puzzle_hash,
        quote.info.underlying_delegated_puzzle_hash,
    );
    check_id(
        errors,
        "eve_coin_id",
        &claimed.eve_coin_id,
        quote.eve_coin.coin_id(),
    );
    check_id(
        errors,
        "eve_p2_puzzle_hash",
        &claimed.eve_p2_puzzle_hash,
        quote.eve_p2_puzzle_hash,
    );
    check_id(
        errors,
        "option_coin_id",
        &claimed.option_coin_id,
        quote.option_coin.coin_id(),
    );
    check_id(
        errors,
        "option_puzzle_hash",
        &claimed.option_puzzle_hash,
        quote.option_puzzle_hash(),
    );
    check_id(errors, "premium_nonce", &claimed.premium_nonce, quote.nonce);
    match quote.premium_payment_hash() {
        Ok(hash) => check_id(
            errors,
            "premium_payment_hash",
            &claimed.premium_payment_hash,
            Bytes32::from(hash),
        ),
        Err(error) => errors.push(format!(
            "the sidecar's `premium_payment_hash` cannot be compared: {error}"
        )),
    }
}

/// Compares one claimed hex id with the value the terms derive.
fn check_id(errors: &mut Vec<String>, field: &'static str, claimed: &Hex, actual: Bytes32) {
    match claimed.bytes32(field) {
        Ok(value) if value == actual => {}
        Ok(value) => errors.push(format!(
            "the sidecar's `{field}` is 0x{value}, but the terms derive 0x{actual}"
        )),
        Err(error) => errors.push(format!("the sidecar's `{field}` is unusable: {error}")),
    }
}

/// Checks that the offer really offers the quoted option, as the terms describe it.
///
/// The option is read from `offered_coins().options`, which `OptionContract::parse_child` populates by
/// running the **inner** eve puzzle. The generic settlement loop in `OfferCoins::parse` finds nothing
/// for an option-only offer, because the singleton top layer rewrites the eve spend's odd create-coin
/// into the curried singleton puzzle hash.
fn check_option(errors: &mut Vec<String>, offer: &Offer, quote: &Quote) {
    let Some(option) = offer.offered_coins().options.get(&quote.launcher_id) else {
        errors.push(format!(
            "the offer does not offer the quoted option (launcher {}): it offers {} option(s)",
            quote.launcher_id,
            offer.offered_coins().options.len()
        ));

        return;
    };

    if option.info.underlying_coin_id != quote.info.underlying_coin_id {
        errors.push(format!(
            "the offer's option locks coin {}, but the terms derive {}",
            option.info.underlying_coin_id, quote.info.underlying_coin_id
        ));
    }

    if option.info.underlying_delegated_puzzle_hash != quote.info.underlying_delegated_puzzle_hash {
        errors.push(format!(
            "the offer's option delegates to {}, but the terms derive {}: the strike or the \
             underlying differs from what the sidecar says",
            option.info.underlying_delegated_puzzle_hash, quote.info.underlying_delegated_puzzle_hash
        ));
    }

    if option.info.p2_puzzle_hash != quote.info.p2_puzzle_hash {
        errors.push(format!(
            "the offer's option is delivered to {}, but the terms require the settlement puzzle {}",
            option.info.p2_puzzle_hash, quote.info.p2_puzzle_hash
        ));
    }

    if option.coin.puzzle_hash != quote.option_puzzle_hash() {
        errors.push(format!(
            "the offered option's puzzle hash is {}, but the terms derive {}",
            option.coin.puzzle_hash,
            quote.option_puzzle_hash()
        ));
    }

    if option.coin.coin_id() != quote.option_coin.coin_id() {
        errors.push(format!(
            "the offered option coin is {}, but the terms derive {}",
            option.coin.coin_id(),
            quote.option_coin.coin_id()
        ));
    }
}

/// Compares the option metadata the launcher commits to with the terms.
///
/// The hashes commit to the expiry and the strike only indirectly, through the delegated puzzle, so
/// reading the launcher solution back is a separate check rather than a redundant one.
fn check_metadata(errors: &mut Vec<String>, metadata: &OptionMetadata, quote: &Quote) {
    if metadata.expiration_seconds != quote.terms.expiry_seconds {
        errors.push(format!(
            "the launcher commits to an expiry of {} seconds, but the sidecar says {}",
            metadata.expiration_seconds, quote.terms.expiry_seconds
        ));
    }

    let strike = match quote.terms.strike_type() {
        Ok(strike) => strike,
        Err(error) => {
            errors.push(format!("the sidecar's strike cannot be read: {error}"));

            return;
        }
    };

    if metadata.strike_type != strike {
        errors.push(format!(
            "the launcher commits to a strike of {:?}, but the sidecar says {:?}",
            metadata.strike_type, strike
        ));
    }
}

/// Reads the `OptionMetadata` out of the launcher spend's solution.
fn launcher_metadata(
    allocator: &mut Allocator,
    launcher_spend: &CoinSpend,
) -> Result<OptionMetadata, SecError> {
    let solution = launcher_spend
        .solution
        .to_clvm(allocator)
        .map_err(DriverError::from)?;

    Ok(OptionContract::parse_metadata(allocator, solution)?)
}

/// Runs one spend and returns its output conditions.
fn run_conditions(
    allocator: &mut Allocator,
    coin_spend: &CoinSpend,
) -> Result<Vec<Condition>, SecError> {
    let puzzle = coin_spend
        .puzzle_reveal
        .to_clvm(allocator)
        .map_err(DriverError::from)?;
    let solution = coin_spend
        .solution
        .to_clvm(allocator)
        .map_err(DriverError::from)?;
    let output = run_puzzle(allocator, puzzle, solution).map_err(DriverError::from)?;

    Ok(Vec::<Condition>::from_clvm(allocator, output).map_err(DriverError::from)?)
}

/// Sorts one spend's conditions into the modeled sets and the unmodeled list.
///
/// A condition is structural — understood, and not reported — when it can only constrain the spend
/// that carries it or a coin inside the bundle: created coins, announcements, the self-assertions the
/// singleton layer emits (`ASSERT_MY_AMOUNT`, `ASSERT_MY_PARENT_ID`), and signature requirements.
/// Everything else is reported rather than failed: the tool has no model for it, which is a reason for
/// a taker to look, not a reason to refuse the offer.
fn collect(allocator: &Allocator, coin_id: Bytes32, conditions: Vec<Condition>, found: &mut Found) {
    for condition in conditions {
        match condition {
            Condition::Remark(_)
            | Condition::CreateCoin(_)
            | Condition::CreateCoinAnnouncement(_)
            | Condition::CreatePuzzleAnnouncement(_)
            | Condition::AssertCoinAnnouncement(_)
            | Condition::AssertMyCoinId(_)
            | Condition::AssertMyParentId(_)
            | Condition::AssertMyPuzzleHash(_)
            | Condition::AssertMyAmount(_)
            | Condition::AssertMyBirthSeconds(_)
            | Condition::AssertMyBirthHeight(_)
            | Condition::AssertEphemeral(_)
            | Condition::AggSigParent(_)
            | Condition::AggSigPuzzle(_)
            | Condition::AggSigAmount(_)
            | Condition::AggSigPuzzleAmount(_)
            | Condition::AggSigParentAmount(_)
            | Condition::AggSigParentPuzzle(_)
            | Condition::AggSigUnsafe(_)
            | Condition::AggSigMe(_) => {}

            Condition::AssertPuzzleAnnouncement(assertion) => {
                found.premium_assertions.push(assertion.announcement_id);
            }

            Condition::AssertBeforeSecondsAbsolute(deadline) => {
                found.take_by.push(deadline.seconds);
            }

            other => found.unmodeled.push(UnmodeledCondition {
                coin_id,
                condition: describe(allocator, other),
            }),
        }
    }
}

/// Renders a condition the verifier does not model.
fn describe(allocator: &Allocator, condition: Condition) -> String {
    match condition {
        Condition::Other(pointer) => Program::from_clvm(allocator, pointer).map_or_else(
            |_| "unmodelled condition".to_string(),
            |program| format!("unmodelled program 0x{}", hex::encode(program.to_vec())),
        ),
        other => format!("{other:?}"),
    }
}

/// Renders a `u64` set for an error message.
fn describe_u64(values: &[u64]) -> String {
    if values.is_empty() {
        "nothing".to_string()
    } else {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Renders a hash set for an error message.
fn describe_bytes32(values: &[Bytes32]) -> String {
    if values.is_empty() {
        "nothing".to_string()
    } else {
        values
            .iter()
            .map(|value| format!("0x{value}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl From<&QuoteSidecar> for SidecarSource {
    fn from(sidecar: &QuoteSidecar) -> Self {
        Self::Sidecar(sidecar.clone())
    }
}

impl From<&SidecarSource> for SidecarSource {
    fn from(source: &SidecarSource) -> Self {
        source.clone()
    }
}

#[cfg(test)]
mod tests {
    use chia_wallet_sdk::chia::bls::sign;

    use crate::build::build_maker_bundle;
    use crate::offer::{OfferFormat, SealedOffer, seal};
    use crate::terms::{
        BackingAsset, BackingCatJson, CoinJson, LineageProofJson, Premium, PremiumAsset,
        QuoteTerms, SINGLETON_AMOUNT, StrikeType,
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
            b"securetheoption verify fixture",
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

    /// The offer a maker would publish for `quote`.
    fn sealed(quote: &Quote) -> Result<SealedOffer, SecError> {
        seal(quote, &signed(quote)?, OfferFormat::Offer)
    }

    #[test]
    fn a_valid_xch_offer_verifies() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = sealed(&quote)?;
        let report = verify(&sealed.spend_bundle, &sealed.sidecar)?;

        assert!(report.unmodeled_conditions.is_empty());
        assert_eq!(report.modeled.take_by, quote.terms.take_by_seconds);
        assert_eq!(
            report.modeled.premium_assertion,
            quote.premium_assertion(&mut SpendContext::new())?.announcement_id
        );
        assert_eq!(
            report.metadata.expiration_seconds,
            quote.terms.expiry_seconds
        );
        assert_eq!(
            report.metadata.strike_type,
            OptionType::Xch { amount: 2_500 }
        );
        assert_eq!(
            report.premium_payment_hash,
            Hex(hex_bytes(
                Bytes32::from(quote.premium_payment_hash()?).to_bytes()
            ))
        );
        assert_eq!(report.quote, quote);

        Ok(())
    }

    #[test]
    fn a_cat_backed_offer_verifies() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let sealed = sealed(&quote)?;
        let report = verify(&sealed.spend_bundle, &sealed.sidecar)?;

        assert!(report.unmodeled_conditions.is_empty());
        assert_eq!(report.quote.launcher_id, quote.launcher_id);
        assert_eq!(
            report.quote.underlying_coin, quote.underlying_coin,
            "the CAT-wrapped lock coin survives the round trip"
        );

        Ok(())
    }

    #[test]
    fn a_cat_premium_offer_verifies() -> anyhow::Result<()> {
        // The settlement placeholder of a CAT premium is not runnable (Verification Note 16), so this
        // also proves verification filters to the maker's own spends instead of running every spend.
        let quote = Quote::new(cat_premium_terms(Some([6; 32])))?;
        let sealed = sealed(&quote)?;
        let report = verify(&sealed.spend_bundle, &sealed.sidecar)?;

        assert!(report.unmodeled_conditions.is_empty());
        assert_eq!(report.quote.nonce, quote.nonce);

        Ok(())
    }

    #[test]
    fn a_bundle_that_does_not_offer_the_option_is_rejected() -> anyhow::Result<()> {
        let quoted = Quote::new(xch_terms(1_000))?;
        let other = Quote::new(xch_terms(2_000))?;

        let sidecar = sealed(&quoted)?.sidecar;
        let foreign = sealed(&other)?;

        let error = verify(&foreign.spend_bundle, &sidecar).unwrap_err();
        assert!(
            error.to_string().contains("does not offer the quoted option"),
            "{error}"
        );

        Ok(())
    }

    #[test]
    fn a_tampered_derived_id_is_rejected() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = sealed(&quote)?;

        let mut sidecar = sealed.sidecar.clone();
        sidecar.derived.launcher_id = hex32([42; 32]);

        let error = verify(&sealed.spend_bundle, &sidecar).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("verification failed"), "{message}");
        assert!(message.contains("launcher_id"), "{message}");

        Ok(())
    }

    #[test]
    fn a_tampered_take_by_is_rejected() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = sealed(&quote)?;

        let mut sidecar = sealed.sidecar.clone();
        sidecar.terms.take_by_seconds += 1;

        // No hash commits to the deadline, so this is exactly the check that catches it.
        let error = verify(&sealed.spend_bundle, &sidecar).unwrap_err();
        assert!(
            error.to_string().contains("AssertBeforeSecondsAbsolute"),
            "{error}"
        );

        Ok(())
    }

    #[test]
    fn a_tampered_premium_is_rejected() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = sealed(&quote)?;

        let mut sidecar = sealed.sidecar.clone();
        sidecar.terms.premium.amount += 1;

        let error = verify(&sealed.spend_bundle, &sidecar).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("premium_payment_hash"), "{message}");
        assert!(message.contains("AssertPuzzleAnnouncement"), "{message}");

        Ok(())
    }

    #[test]
    fn a_tampered_strike_is_rejected() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = sealed(&quote)?;

        let mut sidecar = sealed.sidecar.clone();
        sidecar.terms.strike = StrikeType::Xch { amount: 2_600 };

        let error = verify(&sealed.spend_bundle, &sidecar).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("underlying_delegated_puzzle_hash"),
            "{message}"
        );
        assert!(message.contains("commits to a strike"), "{message}");

        Ok(())
    }

    #[test]
    fn bare_terms_verify_without_the_claims() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let sealed = sealed(&quote)?;

        let report = verify(&sealed.spend_bundle, quote.terms.clone())?;
        assert!(report.unmodeled_conditions.is_empty());

        let mut terms = quote.terms.clone();
        terms.take_by_seconds += 1;

        let error = verify(&sealed.spend_bundle, terms).unwrap_err();
        assert!(
            error.to_string().contains("AssertBeforeSecondsAbsolute"),
            "{error}"
        );

        Ok(())
    }

    #[test]
    fn an_unmodelled_condition_is_reported_but_not_fatal() -> anyhow::Result<()> {
        let mut terms = xch_terms(1_000);
        terms.fee_floor = 7;

        let quote = Quote::new(terms)?;
        let sealed = sealed(&quote)?;
        let report = verify(&sealed.spend_bundle, &sealed.sidecar)?;

        assert_eq!(report.unmodeled_conditions.len(), 1);
        assert!(
            report.unmodeled_conditions[0].condition.contains("ReserveFee"),
            "{:?}",
            report.unmodeled_conditions[0]
        );
        assert_eq!(
            report.unmodeled_conditions[0].coin_id,
            quote.terms.backing_coin()?.coin_id()
        );

        Ok(())
    }

    #[test]
    fn collect_classifies_the_conditions_it_models() -> anyhow::Result<()> {
        let allocator = Allocator::new();
        let coin_id = Bytes32::new([7; 32]);
        let assertion = Bytes32::new([9; 32]);

        let conditions = vec![
            Condition::from(AssertBeforeSecondsAbsolute::new(5)),
            Condition::from(AssertPuzzleAnnouncement::new(assertion)),
            Condition::from(AssertSecondsAbsolute::new(100)),
            Condition::from(ReserveFee::new(3)),
        ];

        let mut found = Found::default();
        collect(&allocator, coin_id, conditions, &mut found);

        assert_eq!(found.take_by, vec![5]);
        assert_eq!(found.premium_assertions, vec![assertion]);
        assert_eq!(found.unmodeled.len(), 2);
        assert!(
            found
                .unmodeled
                .iter()
                .all(|condition| condition.coin_id == coin_id)
        );

        Ok(())
    }
}

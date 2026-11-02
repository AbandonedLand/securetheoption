//! The CAT-backed maker spend bundle.
//!
//! A CAT cannot fund a singleton launcher: the launcher coin's puzzle hash is pinned to
//! `SINGLETON_LAUNCHER_HASH`, and a CAT spend can only create CAT-wrapped coins. A CAT-backed quote
//! therefore commits a second, XCH coin holding exactly one mojo whose only job is to create the
//! launcher coin, while the CAT coin itself carries the premium assertion, the take-by deadline and
//! the underlying lock.
//!
//! The CAT coin is spent through `Cat::spend_all` rather than a bare `SpendContext::spend`: the ring
//! announcements, the neighbour proofs and the `prev_subtotal` are derived from the ring, and a
//! hand-written solution that gets them wrong produces an unspendable coin rather than a build error.

use chia_wallet_sdk::prelude::*;

use crate::error::SecError;
use crate::quote::Quote;

use super::{backing_assertions, canonical, mint_eve_option};

/// The CAT-backed spends, in canonical order: the CAT coin, the XCH launcher coin, the launcher coin
/// and the eve option.
pub(super) fn build_cat(quote: &Quote) -> Result<Vec<CoinSpend>, SecError> {
    let terms = &quote.terms;
    let mut ctx = SpendContext::new();

    let maker_layer = StandardLayer::new(terms.maker_public_key()?);
    let maker_puzzle_hash = terms.maker_puzzle_hash()?;
    let backing_coin = terms.backing_coin()?;
    let launcher_coin = terms
        .launcher_coin()?
        .ok_or_else(|| SecError::terms("a CAT backing coin requires an XCH `launcher_coin`"))?;
    let cat_terms = terms
        .backing_cat()?
        .ok_or_else(|| SecError::terms("a CAT backing coin is required here"))?;

    // The launcher and eve spends, plus the create-coin and the announcement their parent owes.
    let (launcher_create_coin, launcher_announcement) = mint_eve_option(&mut ctx, quote)?;

    // The launcher coin is XCH, so its parent spend has to be XCH too: the CAT layer would wrap an
    // inner `create_coin` of `SINGLETON_LAUNCHER_HASH` into a CAT coin. This coin holds exactly
    // `SINGLETON_AMOUNT` (enforced by `QuoteTerms::validate_cat`), which is exactly what the launcher
    // turns into the eve coin, so it creates no change and burns nothing.
    maker_layer.spend(
        &mut ctx,
        launcher_coin,
        Conditions::new()
            .with(launcher_create_coin)
            .extend(launcher_announcement),
    )?;

    // The CAT ring has to net to zero, so every CAT the quote does not lock has to come back as CAT
    // change. The `SINGLETON_AMOUNT` reservation from the XCH path has no counterpart here: the
    // launcher coin already funds the singleton out of its own mojo.
    let change = backing_coin
        .amount
        .checked_sub(terms.underlying_amount)
        .ok_or_else(|| {
            SecError::terms(format!(
                "the CAT backing coin holds {}, which cannot fund the {} locked by the option",
                backing_coin.amount, terms.underlying_amount
            ))
        })?;

    // The lock's `create_coin` names the *inner* p2 puzzle hash; the CAT layer wraps it, which is why
    // `quote.underlying_coin` carries the CAT-wrapped hash of the same puzzle.
    let mut conditions = Conditions::new().create_coin(
        quote.underlying_p2_puzzle_hash(),
        terms.underlying_amount,
        Memos::None,
    );

    if change > 0 {
        conditions = conditions.create_coin(maker_puzzle_hash, change, Memos::None);
    }

    let conditions = conditions.extend(backing_assertions(&mut ctx, quote)?);
    let p2_spend = maker_layer.spend_with_conditions(&mut ctx, conditions)?;

    let cat = Cat::new(
        backing_coin,
        Some(cat_terms.lineage_proof),
        CatInfo::new(
            cat_terms.asset_id,
            cat_terms.hidden_puzzle_hash,
            maker_puzzle_hash,
        ),
    );

    // A one-coin ring: `spend_all` announces and asserts this coin's own ring announcement, so the
    // CAT delta has to be exactly zero — which is what the change coin above guarantees.
    Cat::spend_all(&mut ctx, &[CatSpend::new(cat, p2_spend)])?;

    Ok(canonical(ctx.take()))
}

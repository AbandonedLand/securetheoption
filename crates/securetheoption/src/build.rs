//! The maker's spend bundle: what a taker completes when they accept a quote.
//!
//! The bundle is assembled by hand rather than through `Spends` or `MintOptionAction`.
//! `Spends::prepare` -> `create_change` -> `SingletonSpends::finalize` spends the eve option into a
//! change coin when no destination is set, which would destroy the coin being offered, and
//! `MintOptionAction` both refuses settlement-sourced spends and hardcodes the owner puzzle hash to
//! the funding coin's p2 with no seam for the premium assertions. Three spends are all this needs
//! for an XCH backing coin: the maker's coin (which creates the launcher coin, the underlying lock
//! and the change), the launcher coin, and the eve option. A CAT backing coin adds a fourth, because
//! the launcher is XCH-only; see [`cat`].
//!
//! Nothing here signs. The bundle leaves this module carrying the identity signature; the maker
//! signs it out of process and the sealing step binds the result into an offer.

use chia_wallet_sdk::prelude::*;
use chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH;

use crate::error::SecError;
use crate::quote::Quote;
use crate::terms::{BackingAsset, LAUNCHER_AMOUNT, SINGLETON_AMOUNT};

pub mod cat;

/// Builds the maker's unsigned spend bundle for `quote`.
///
/// The result is deliberately not landable on its own: the backing spend asserts the taker's
/// premium payment, and only a settlement coin belonging to a taker can announce it. That is the
/// point — the maker's coin cannot be spent into the quote without the premium being paid.
pub fn build_maker_bundle(quote: &Quote) -> Result<SpendBundle, SecError> {
    let coin_spends = match &quote.terms.underlying {
        BackingAsset::Xch { .. } => build_xch(quote)?,
        BackingAsset::Cat { .. } => cat::build_cat(quote)?,
    };

    Ok(SpendBundle::new(coin_spends, Signature::default()))
}

/// The three spends of an XCH-backed quote, in canonical order.
fn build_xch(quote: &Quote) -> Result<Vec<CoinSpend>, SecError> {
    let terms = &quote.terms;
    let mut ctx = SpendContext::new();

    let maker_layer = StandardLayer::new(terms.maker_public_key()?);
    let maker_puzzle_hash = terms.maker_puzzle_hash()?;
    let backing_coin = terms.backing_coin()?;

    let (launcher_create_coin, launcher_announcement) = mint_eve_option(&mut ctx, quote)?;

    // The 0-amount launcher coin is spent into a `SINGLETON_AMOUNT` singleton, so the maker has to
    // part with that mojo as well as the lock; anything else would fail validation as an unbalanced
    // bundle rather than as a fee.
    let change = backing_coin
        .amount
        .checked_sub(terms.underlying_amount)
        .and_then(|remaining| remaining.checked_sub(SINGLETON_AMOUNT))
        .ok_or_else(|| {
            SecError::terms(format!(
                "the XCH backing coin holds {} mojos, which cannot fund the {} locked by the option \
                 plus the {SINGLETON_AMOUNT} mojo option singleton",
                backing_coin.amount, terms.underlying_amount
            ))
        })?;

    let conditions = Conditions::new()
        .with(launcher_create_coin)
        .create_coin(
            quote.underlying_p2_puzzle_hash(),
            terms.underlying_amount,
            Memos::None,
        )
        .create_coin(maker_puzzle_hash, change, Memos::None)
        .extend(launcher_announcement)
        .extend(backing_assertions(&mut ctx, quote)?);

    maker_layer.spend(&mut ctx, backing_coin, conditions)?;

    Ok(canonical(ctx.take()))
}

/// Creates the launcher coin, spends the launcher and spends the eve option.
///
/// Returns the create-coin that the launcher's **parent** spend has to emit, and the conditions
/// (a coin announcement assertion) that same parent spend has to carry. For an XCH backing coin the
/// parent is the backing coin itself; for a CAT backing coin it is the dedicated XCH `launcher_coin`.
///
/// The eve option is delivered to `SETTLEMENT_PAYMENT_HASH` so that a taker can take it: the offer
/// parser only recognises an option whose inner p2 is the settlement puzzle.
fn mint_eve_option(
    ctx: &mut SpendContext,
    quote: &Quote,
) -> Result<(CreateCoin<NodePtr>, Conditions), SecError> {
    let terms = &quote.terms;
    let owner: Bytes32 = SETTLEMENT_PAYMENT_HASH.into();

    let (launcher_create_coin, launcher) = OptionLauncher::create_early(
        ctx,
        quote.launcher_parent_coin.coin_id(),
        LAUNCHER_AMOUNT,
        OptionLauncherInfo::new(
            terms.creator_puzzle_hash()?,
            owner,
            terms.expiry_seconds,
            terms.underlying_amount,
            terms.strike_type()?,
        ),
        SINGLETON_AMOUNT,
    )?;

    let launcher = launcher.with_underlying(quote.underlying_coin.coin_id());

    // Spending the launcher inserts its own coin spend and yields the announcement its parent must
    // assert, which is what binds the parent and launcher spends into one bundle.
    let (launcher_announcement, eve_option) = launcher.mint_eve(ctx, quote.eve_p2_puzzle_hash)?;

    // The same `clvm_quote` of `create_coin(owner, SINGLETON_AMOUNT)` that `eve_p2_puzzle_hash`
    // commits to, so the child is exactly `quote.option_coin`.
    let memos = ctx.hint(owner)?;
    let eve_inner_spend =
        ctx.delegated_spend(Conditions::new().create_coin(owner, SINGLETON_AMOUNT, memos))?;

    let _option = eve_option.spend(ctx, eve_inner_spend)?;

    Ok((launcher_create_coin, launcher_announcement))
}

/// The assertions every maker backing spend carries.
///
/// The premium assertion and the take-by deadline sit on the coin whose spending cancels the offer,
/// which is the coin the offer's nonce is derived from. The fee floor is the taker's obligation: the
/// maker bundle never creates a fee, it only refuses to land without one.
fn backing_assertions(ctx: &mut SpendContext, quote: &Quote) -> Result<Conditions, SecError> {
    let mut conditions = Conditions::new()
        .with(quote.premium_assertion(ctx)?)
        .assert_before_seconds_absolute(quote.terms.take_by_seconds);

    if quote.terms.fee_floor > 0 {
        conditions = conditions.reserve_fee(quote.terms.fee_floor);
    }

    Ok(conditions)
}

/// Sorts the spends into an order derived from their content.
///
/// Sealing rebuilds the bundle and compares it to the externally signed one element by element, so
/// the order must be a function of the bundle rather than of the order the spends happened to be
/// built in. Chia ignores spend order, so this costs nothing.
fn canonical(mut coin_spends: Vec<CoinSpend>) -> Vec<CoinSpend> {
    coin_spends.sort_by_key(|coin_spend| coin_spend.coin.coin_id());
    coin_spends
}

#[cfg(test)]
mod tests {
    use chia_wallet_sdk::puzzles::{SINGLETON_LAUNCHER, SINGLETON_LAUNCHER_HASH};

    use crate::terms::{
        BackingCatJson, CoinJson, Hex, LineageProofJson, Premium, PremiumAsset, QuoteTerms,
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

    /// A CAT terms fixture whose lineage proof is self-consistent.
    ///
    /// The CAT puzzle does not merely read its lineage proof: `is_parent_cat` recomputes the parent
    /// coin id from `(parent_parent_coin_info, cat_puzzle_hash(parent_inner_puzzle_hash),
    /// parent_amount)` and asserts it equals the coin's own parent coin id. A fixture with arbitrary
    /// proof fields therefore builds fine but cannot be *run*, and these tests have to run it to
    /// inspect the spends.
    fn cat_terms() -> QuoteTerms {
        let (maker_public_key, maker_puzzle_hash) = maker();
        let asset_id = Bytes32::new([5; 32]);

        let parent_parent_coin_info = Bytes32::new([2; 32]);
        let parent_inner_puzzle_hash = Bytes32::new([3; 32]);
        let parent_amount = 5_000;
        let parent_puzzle_hash: Bytes32 = CatInfo::new(asset_id, None, parent_inner_puzzle_hash)
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

    /// The same CAT quote with a different backing amount, for the change-coin cases.
    fn cat_terms_with_amount(backing_amount: u64) -> QuoteTerms {
        let mut terms = cat_terms();
        let BackingAsset::Cat { coin, .. } = &mut terms.underlying else {
            panic!("expected a CAT backing coin");
        };
        coin.amount = backing_amount;
        terms
    }

    fn spend_conditions(
        allocator: &mut Allocator,
        coin_spend: &CoinSpend,
    ) -> anyhow::Result<Vec<Condition>> {
        let puzzle = coin_spend.puzzle_reveal.to_clvm(allocator)?;
        let solution = coin_spend.solution.to_clvm(allocator)?;
        let output = run_puzzle(allocator, puzzle, solution)?;

        Ok(Vec::<Condition>::from_clvm(allocator, output)?)
    }

    fn created_coins(
        allocator: &mut Allocator,
        coin_spend: &CoinSpend,
    ) -> anyhow::Result<Vec<Coin>> {
        Ok(spend_conditions(allocator, coin_spend)?
            .iter()
            .filter_map(|condition| condition.as_create_coin())
            .map(|create_coin| {
                Coin::new(
                    coin_spend.coin.coin_id(),
                    create_coin.puzzle_hash,
                    create_coin.amount,
                )
            })
            .collect())
    }

    fn spend_for(bundle: &SpendBundle, coin: Coin) -> &CoinSpend {
        bundle
            .coin_spends
            .iter()
            .find(|coin_spend| coin_spend.coin == coin)
            .expect("the bundle spends the coin the quote names")
    }

    fn totals(bundle: &SpendBundle) -> anyhow::Result<(u64, u64)> {
        let mut allocator = Allocator::new();
        let mut removed = 0;
        let mut created = 0;

        for coin_spend in &bundle.coin_spends {
            removed += coin_spend.coin.amount;

            for coin in created_coins(&mut allocator, coin_spend)? {
                created += coin.amount;
            }
        }

        Ok((removed, created))
    }

    #[test]
    fn xch_bundle_spends_exactly_the_three_coins() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let bundle = build_maker_bundle(&quote)?;

        assert_eq!(bundle.coin_spends.len(), 3);

        let mut spent: Vec<Coin> = bundle
            .coin_spends
            .iter()
            .map(|coin_spend| coin_spend.coin)
            .collect();
        spent.sort_by_key(|coin| coin.coin_id());

        let mut expected = vec![
            quote.terms.backing_coin()?,
            quote.launcher_coin,
            quote.eve_coin,
        ];
        expected.sort_by_key(|coin| coin.coin_id());

        assert_eq!(spent, expected);

        Ok(())
    }

    #[test]
    fn xch_bundle_leaves_signing_to_the_maker() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let bundle = build_maker_bundle(&quote)?;

        assert_eq!(bundle.aggregated_signature, Signature::default());

        Ok(())
    }

    #[test]
    fn xch_bundle_distributes_every_mojo() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let bundle = build_maker_bundle(&quote)?;

        let (removed, created) = totals(&bundle)?;

        // Nothing burned, nothing conjured. This is what pins the 1-mojo singleton reservation: a
        // change coin computed as `backing - underlying` alone would conjure a mojo here.
        assert_eq!(removed, created);
        assert_eq!(removed, 1_001);

        Ok(())
    }

    #[test]
    fn maker_spend_creates_the_launcher_the_lock_and_the_change() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let terms = &quote.terms;
        let bundle = build_maker_bundle(&quote)?;
        let backing = spend_for(&bundle, terms.backing_coin()?);

        let mut allocator = Allocator::new();
        let created = created_coins(&mut allocator, backing)?;
        assert_eq!(created.len(), 3);

        let launcher = created
            .iter()
            .find(|coin| coin.puzzle_hash == SINGLETON_LAUNCHER_HASH.into())
            .expect("the maker spend creates the launcher coin");
        assert_eq!(launcher.amount, LAUNCHER_AMOUNT);
        assert_eq!(*launcher, quote.launcher_coin);

        let lock = created
            .iter()
            .find(|coin| coin.coin_id() == quote.underlying_coin.coin_id())
            .expect("the maker spend locks the underlying");
        assert_eq!(lock.puzzle_hash, quote.underlying_p2_puzzle_hash());
        assert_eq!(lock.amount, terms.underlying_amount);

        let maker_puzzle_hash = terms.maker_puzzle_hash()?;
        let change = created
            .iter()
            .find(|coin| coin.puzzle_hash == maker_puzzle_hash)
            .expect("the maker spend returns change");
        assert_eq!(
            change.amount,
            1_000 - terms.underlying_amount - SINGLETON_AMOUNT
        );

        Ok(())
    }

    #[test]
    fn backing_spend_carries_the_premium_the_deadline_and_the_launcher() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let bundle = build_maker_bundle(&quote)?;
        let backing = spend_for(&bundle, quote.terms.backing_coin()?);

        let mut ctx = SpendContext::new();
        let premium = quote.premium_assertion(&mut ctx)?;

        let mut allocator = Allocator::new();
        let conditions = spend_conditions(&mut allocator, backing)?;

        let premiums: Vec<AssertPuzzleAnnouncement> = conditions
            .iter()
            .filter_map(Condition::as_assert_puzzle_announcement)
            .copied()
            .collect();
        assert_eq!(premiums, vec![premium]);

        let deadlines: Vec<AssertBeforeSecondsAbsolute> = conditions
            .iter()
            .filter_map(Condition::as_assert_before_seconds_absolute)
            .copied()
            .collect();
        assert_eq!(
            deadlines,
            vec![AssertBeforeSecondsAbsolute::new(
                quote.terms.take_by_seconds
            )]
        );

        let announcements = conditions
            .iter()
            .filter(|condition| condition.as_assert_coin_announcement().is_some())
            .count();
        assert_eq!(announcements, 1);

        // The other two spends assert nothing. The maker's coin is the only one whose spending also
        // cancels the offer, so it is the only one that has to be bound to the premium.
        for coin in [quote.launcher_coin, quote.eve_coin] {
            let conditions = spend_conditions(&mut allocator, spend_for(&bundle, coin))?;
            assert!(conditions.iter().all(|condition| {
                condition.as_assert_puzzle_announcement().is_none()
                    && condition.as_assert_before_seconds_absolute().is_none()
                    && condition.as_assert_coin_announcement().is_none()
            }));
        }

        Ok(())
    }

    #[test]
    fn launcher_and_eve_spends_are_shaped_as_the_offer_expects() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let bundle = build_maker_bundle(&quote)?;

        let launcher = spend_for(&bundle, quote.launcher_coin);
        assert_eq!(launcher.puzzle_reveal.to_vec(), SINGLETON_LAUNCHER.to_vec());

        let mut allocator = Allocator::new();
        let created = created_coins(&mut allocator, spend_for(&bundle, quote.eve_coin))?;

        // The eve spend reveals the full option-contract puzzle, so its output is the *morphed*
        // condition: the singleton top layer rewrites an odd `CREATE_COIN` into the curried full
        // puzzle hash. The child is therefore exactly the quoted option, and no `create_coin` in the
        // bundle names the settlement puzzle (Verification Note 15).
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].amount, SINGLETON_AMOUNT);
        assert_eq!(created[0].coin_id(), quote.option_coin.coin_id());
        assert_eq!(created[0].puzzle_hash, quote.option_coin.puzzle_hash);
        assert_ne!(created[0].puzzle_hash, SETTLEMENT_PAYMENT_HASH.into());

        Ok(())
    }

    #[test]
    fn fee_floor_is_a_reserve_fee_on_the_backing_spend() -> anyhow::Result<()> {
        let mut terms = xch_terms(1_000);
        terms.fee_floor = 7;

        let quote = Quote::new(terms)?;
        let bundle = build_maker_bundle(&quote)?;
        let backing = spend_for(&bundle, quote.terms.backing_coin()?);

        let mut allocator = Allocator::new();
        let conditions = spend_conditions(&mut allocator, backing)?;
        let floors: Vec<u64> = conditions
            .iter()
            .filter_map(Condition::as_reserve_fee)
            .map(|reserve_fee| reserve_fee.amount)
            .collect();
        assert_eq!(floors, vec![7]);

        // The floor is the taker's obligation, not the maker's burn: the bundle still balances.
        let (removed, created) = totals(&bundle)?;
        assert_eq!(removed, created);

        Ok(())
    }

    #[test]
    fn the_bundle_registers_the_option_it_offers() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;
        let bundle = build_maker_bundle(&quote)?;

        let mut ctx = SpendContext::new();
        let requested_payments = quote.requested_payments(&mut ctx)?;
        let asset_info = quote.asset_info()?;
        let offer =
            Offer::from_input_spend_bundle(&mut ctx, bundle, requested_payments, asset_info)?;

        let option = offer
            .offered_coins()
            .options
            .get(&quote.launcher_id)
            .expect("the offer offers the quoted option");

        assert_eq!(option.coin, quote.option_coin);
        assert_eq!(option.info, quote.info);

        // `OfferCoins::parse` also scans every maker spend's full-puzzle output for settlement-puzzle
        // coins. The singleton top layer morphs the option's odd create away from the settlement
        // puzzle, so nothing is misfiled as offered XCH: an option-only offer offers no XCH at all
        // (Verification Note 15).
        assert!(offer.offered_coins().xch.is_empty());
        assert_eq!(offer.offered_coins().amounts().xch, 0);

        // The maker bundle asks for no fee of its own.
        assert_eq!(offer.fee()?, 0);

        Ok(())
    }

    #[test]
    fn the_bundle_is_reproducible() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(1_000))?;

        let first = build_maker_bundle(&quote)?;
        let second = build_maker_bundle(&quote)?;

        // Sealing compares an externally signed bundle to a rebuild element by element, so the
        // spends have to come out in the same order with byte-identical reveals and solutions.
        assert_eq!(first.coin_spends.len(), second.coin_spends.len());

        for (left, right) in first.coin_spends.iter().zip(&second.coin_spends) {
            assert_eq!(left.coin, right.coin);
            assert_eq!(left.puzzle_reveal.to_vec(), right.puzzle_reveal.to_vec());
            assert_eq!(left.solution.to_vec(), right.solution.to_vec());
        }

        Ok(())
    }
    #[test]
    fn cat_bundle_spends_exactly_the_four_coins() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let bundle = build_maker_bundle(&quote)?;

        assert_eq!(bundle.coin_spends.len(), 4);

        let mut spent: Vec<Coin> = bundle
            .coin_spends
            .iter()
            .map(|coin_spend| coin_spend.coin)
            .collect();
        spent.sort_by_key(|coin| coin.coin_id());

        let mut expected = vec![
            quote.terms.backing_coin()?,
            quote.terms.launcher_coin()?.expect("launcher coin"),
            quote.launcher_coin,
            quote.eve_coin,
        ];
        expected.sort_by_key(|coin| coin.coin_id());

        assert_eq!(spent, expected);

        Ok(())
    }

    #[test]
    fn cat_bundle_leaves_signing_to_the_maker() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let bundle = build_maker_bundle(&quote)?;

        assert_eq!(bundle.aggregated_signature, Signature::default());

        Ok(())
    }

    #[test]
    fn cat_bundle_distributes_every_mojo() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let bundle = build_maker_bundle(&quote)?;

        let (removed, created) = totals(&bundle)?;

        // Four spends, so four removals: 1_000 in the CAT, 1 in the XCH launcher coin, 0 in the
        // launcher coin the XCH spend creates, and 1 in the eve coin the launcher creates. The CAT
        // stays inside its ring (lock only, no change at 1:1); the three XCH coins carry two mojos,
        // which become the 0-amount launcher coin, the 1-mojo eve coin and the offered option.
        assert_eq!(removed, created);
        assert_eq!(removed, 1_002);

        Ok(())
    }

    #[test]
    fn cat_spend_creates_the_cat_lock_and_the_cat_change() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms_with_amount(1_500))?;
        let cat_terms = quote.terms.backing_cat()?.expect("CAT backing");
        let bundle = build_maker_bundle(&quote)?;

        let mut allocator = Allocator::new();
        let created = created_coins(
            &mut allocator,
            spend_for(&bundle, quote.terms.backing_coin()?),
        )?;

        assert_eq!(created.len(), 2);

        let lock = created
            .iter()
            .find(|coin| coin.coin_id() == quote.underlying_coin.coin_id())
            .expect("the CAT spend locks the underlying");
        assert_eq!(lock.amount, 1_000);
        assert_eq!(lock.puzzle_hash, quote.underlying_coin.puzzle_hash);
        assert_ne!(lock.puzzle_hash, quote.underlying_p2_puzzle_hash());

        let change_puzzle_hash: Bytes32 =
            CatInfo::new(cat_terms.asset_id, None, quote.terms.maker_puzzle_hash()?)
                .puzzle_hash()
                .into();
        let change = created
            .iter()
            .find(|coin| coin.puzzle_hash == change_puzzle_hash)
            .expect("the CAT spend returns CAT change");
        assert_eq!(change.amount, 500);

        Ok(())
    }

    #[test]
    fn the_cat_change_is_omitted_when_the_lock_is_the_whole_coin() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let bundle = build_maker_bundle(&quote)?;

        let mut allocator = Allocator::new();
        let created = created_coins(
            &mut allocator,
            spend_for(&bundle, quote.terms.backing_coin()?),
        )?;

        assert_eq!(created.len(), 1);
        assert_eq!(created[0].coin_id(), quote.underlying_coin.coin_id());

        Ok(())
    }

    #[test]
    fn the_launcher_coin_is_funded_by_its_own_one_mojo() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let bundle = build_maker_bundle(&quote)?;
        let launcher_coin = quote.terms.launcher_coin()?.expect("launcher coin");
        let spend = spend_for(&bundle, launcher_coin);

        let mut allocator = Allocator::new();
        let created = created_coins(&mut allocator, spend)?;

        // A 1-mojo XCH coin cannot return change: everything it holds becomes the 0-amount launcher
        // coin, and the launcher itself creates the 1-mojo singleton.
        assert_eq!(created, vec![quote.launcher_coin]);
        assert_eq!(quote.launcher_coin.amount, LAUNCHER_AMOUNT);

        let conditions = spend_conditions(&mut allocator, spend)?;
        assert_eq!(
            conditions
                .iter()
                .filter(|condition| condition.as_assert_coin_announcement().is_some())
                .count(),
            1
        );
        assert!(conditions.iter().all(|condition| {
            condition.as_assert_puzzle_announcement().is_none()
                && condition.as_assert_before_seconds_absolute().is_none()
        }));

        Ok(())
    }

    #[test]
    fn cat_spend_carries_the_premium_the_deadline_and_the_ring() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let bundle = build_maker_bundle(&quote)?;

        let mut ctx = SpendContext::new();
        let premium = quote.premium_assertion(&mut ctx)?;

        let mut allocator = Allocator::new();
        let conditions = spend_conditions(
            &mut allocator,
            spend_for(&bundle, quote.terms.backing_coin()?),
        )?;

        let premiums: Vec<AssertPuzzleAnnouncement> = conditions
            .iter()
            .filter_map(Condition::as_assert_puzzle_announcement)
            .copied()
            .collect();
        assert_eq!(premiums, vec![premium]);

        let deadlines: Vec<AssertBeforeSecondsAbsolute> = conditions
            .iter()
            .filter_map(Condition::as_assert_before_seconds_absolute)
            .copied()
            .collect();
        assert_eq!(
            deadlines,
            vec![AssertBeforeSecondsAbsolute::new(
                quote.terms.take_by_seconds
            )]
        );

        // The CAT layer adds its own ring announcement pair; the maker's conditions ride alongside
        // rather than replacing them. A one-coin ring creates one announcement and asserts one.
        let announced = conditions
            .iter()
            .filter(|condition| condition.as_create_coin_announcement().is_some())
            .count();
        let asserted = conditions
            .iter()
            .filter(|condition| condition.as_assert_coin_announcement().is_some())
            .count();
        assert_eq!((announced, asserted), (1, 1));

        Ok(())
    }

    #[test]
    fn cat_fee_floor_is_a_reserve_fee_on_the_cat_spend() -> anyhow::Result<()> {
        let mut terms = cat_terms();
        terms.fee_floor = 7;

        let quote = Quote::new(terms)?;
        let bundle = build_maker_bundle(&quote)?;

        let mut allocator = Allocator::new();
        let conditions = spend_conditions(
            &mut allocator,
            spend_for(&bundle, quote.terms.backing_coin()?),
        )?;
        let floors: Vec<u64> = conditions
            .iter()
            .filter_map(Condition::as_reserve_fee)
            .map(|reserve_fee| reserve_fee.amount)
            .collect();
        assert_eq!(floors, vec![7]);

        // The floor is the taker's obligation, not the maker's burn: the bundle still balances.
        let (removed, created) = totals(&bundle)?;
        assert_eq!(removed, created);

        Ok(())
    }

    #[test]
    fn the_cat_bundle_offers_the_option_and_commits_both_coins() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let bundle = build_maker_bundle(&quote)?;

        let mut ctx = SpendContext::new();
        let requested_payments = quote.requested_payments(&mut ctx)?;
        let asset_info = quote.asset_info()?;
        let offer =
            Offer::from_input_spend_bundle(&mut ctx, bundle, requested_payments, asset_info)?;

        let option = offer
            .offered_coins()
            .options
            .get(&quote.launcher_id)
            .expect("the offer offers the quoted option");
        assert_eq!(option.coin, quote.option_coin);
        assert_eq!(option.info, quote.info);

        // The CAT lock and its change belong to the option and the maker, not to a taker: neither
        // sits at the settlement puzzle, so nothing is offered as a CAT or as XCH.
        assert!(offer.offered_coins().cats.is_empty());
        assert!(offer.offered_coins().xch.is_empty());

        let mut cancellable: Vec<Bytes32> = offer
            .cancellable_coin_spends()?
            .into_iter()
            .map(|coin_spend| coin_spend.coin.coin_id())
            .collect();
        cancellable.sort();

        let mut expected = vec![
            quote.terms.backing_coin()?.coin_id(),
            quote
                .terms
                .launcher_coin()?
                .expect("launcher coin")
                .coin_id(),
        ];
        expected.sort();

        // Both of the maker's own coins are cancellable, and the quote's nonce covers exactly them.
        assert_eq!(cancellable, expected);
        assert_eq!(Offer::nonce(cancellable), quote.nonce);
        assert_eq!(offer.fee()?, 0);

        Ok(())
    }

    #[test]
    fn the_cat_bundle_is_reproducible() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;

        let first = build_maker_bundle(&quote)?;
        let second = build_maker_bundle(&quote)?;

        assert_eq!(first.coin_spends.len(), second.coin_spends.len());

        for (left, right) in first.coin_spends.iter().zip(&second.coin_spends) {
            assert_eq!(left.coin, right.coin);
            assert_eq!(left.puzzle_reveal.to_vec(), right.puzzle_reveal.to_vec());
            assert_eq!(left.solution.to_vec(), right.solution.to_vec());
        }

        Ok(())
    }
}

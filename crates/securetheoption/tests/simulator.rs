//! End-to-end tests against the SDK simulator: a quote becomes an offer, and an offer becomes a live
//! option.
//!
//! Everything here goes through the crate's public surface — [`Quote`], [`build_maker_bundle`],
//! [`seal`], [`verify`] — and nothing is re-derived by hand, so a change to the derivation chain shows
//! up here rather than passing silently. The taker's half uses the SDK's action system, which is the
//! same path a stock wallet takes; it is test code, not a product surface (see `## Scope`, "Not
//! Building").
//!
//! The failures the two negative tests pin are invisible to a unit test: the maker bundle is only
//! landable *with* a taker's premium payment (Verification Note 4), and the take-by deadline is
//! exclusive (Verification Note 5). This file is also the first end-to-end proof of an
//! in-bundle-minted option inside an offer (Verification Note 12), for both XCH and CAT backing.

use chia_wallet_sdk::chia::consensus::validation_error::ErrorCode;
use chia_wallet_sdk::prelude::*;
use chia_wallet_sdk::puzzles::{SETTLEMENT_PAYMENT_HASH, SINGLETON_LAUNCHER_HASH};
use chia_wallet_sdk::test::sign_transaction;
use indexmap::IndexMap;
use securetheoption::{
    BackingAsset, BackingCatJson, CoinJson, Hex, LineageProofJson, OfferFormat, Premium,
    PremiumAsset, Quote, QuoteTerms, SINGLETON_AMOUNT, SealedOffer, StrikeType, build_maker_bundle,
    seal, verify,
};

/// `0x`-prefixed lowercase hex, the form every id takes in a terms document.
fn hex_bytes(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// A funded maker, a funded taker, and the terms tying them together.
///
/// The XCH coins come from [`Simulator::bls`], so the maker's standard-layer puzzle hash the terms
/// carry and the coin the quote spends are derived from the same key: no key material is hardcoded
/// anywhere in this crate.
struct Fixture {
    sim: Simulator,
    maker: BlsPairWithCoin,
    taker: BlsPairWithCoin,
    terms: QuoteTerms,
}

fn premium() -> Premium {
    Premium {
        recipient_puzzle_hash: Hex::new(hex_bytes([11; 32])),
        amount: 25,
        asset: PremiumAsset::Xch,
    }
}

/// An XCH-backed quote: one coin funds the launcher coin, the underlying lock and the change.
fn fixture() -> Fixture {
    let mut sim = Simulator::new();
    let maker = sim.bls(1_000);
    let taker = sim.bls(1_000);

    let terms = QuoteTerms {
        maker_public_key: Hex::new(hex_bytes(maker.pk.to_bytes())),
        creator_puzzle_hash: Hex::new(hex_bytes([9; 32])),
        underlying: BackingAsset::Xch {
            coin: CoinJson {
                parent_coin_info: Hex::new(hex_bytes(maker.coin.parent_coin_info.to_bytes())),
                puzzle_hash: Hex::new(hex_bytes(maker.coin.puzzle_hash.to_bytes())),
                amount: maker.coin.amount,
            },
        },
        underlying_amount: 500,
        strike: StrikeType::Xch { amount: 2_500 },
        expiry_seconds: 1_700_000_000,
        take_by_seconds: 1_710_000_000,
        premium: premium(),
        launcher_coin: None,
        fee_floor: 0,
    };

    Fixture {
        sim,
        maker,
        taker,
        terms,
    }
}

/// A CAT-backed quote with a CAT strike, so the CAT-curried settlement puzzle is committed into
/// `underlying_delegated_puzzle_hash` (FR12).
fn cat_fixture() -> Fixture {
    let mut sim = Simulator::new();
    let maker = sim.bls(1_000);
    let taker = sim.bls(1_000);

    let asset_id = Bytes32::new([5; 32]);
    let parent_parent_coin_info = Bytes32::new([2; 32]);
    let parent_inner_puzzle_hash = Bytes32::new([3; 32]);
    let parent_amount = 5_000;

    // The CAT puzzle does not merely read its lineage proof: it recomputes the parent coin id from
    // the proof fields and asserts it matches. A fixture with arbitrary proof fields therefore builds
    // fine but cannot be *run*, and this test has to run it.
    let parent_puzzle_hash: Bytes32 = CatInfo::new(asset_id, None, parent_inner_puzzle_hash)
        .puzzle_hash()
        .into();
    let parent_coin_id =
        Coin::new(parent_parent_coin_info, parent_puzzle_hash, parent_amount).coin_id();

    let backing_puzzle_hash: Bytes32 = CatInfo::new(asset_id, None, maker.puzzle_hash)
        .puzzle_hash()
        .into();
    let backing_coin = Coin::new(parent_coin_id, backing_puzzle_hash, 1_000);

    // Inserted rather than created: `Simulator::new_coin` would hand out a random parent coin id,
    // which could not match the lineage proof above.
    sim.insert_coin(backing_coin);

    // A singleton launcher is XCH-only — the launcher coin's puzzle hash is pinned to
    // `SINGLETON_LAUNCHER_HASH`, and a CAT spend can only create CAT-wrapped coins — so a CAT-backed
    // quote commits a second, 1-mojo XCH coin whose only job is to create the launcher coin.
    let launcher_coin = sim.new_coin(maker.puzzle_hash, SINGLETON_AMOUNT);

    let terms = QuoteTerms {
        maker_public_key: Hex::new(hex_bytes(maker.pk.to_bytes())),
        creator_puzzle_hash: Hex::new(hex_bytes([9; 32])),
        underlying: BackingAsset::Cat {
            coin: CoinJson {
                parent_coin_info: Hex::new(hex_bytes(backing_coin.parent_coin_info.to_bytes())),
                puzzle_hash: Hex::new(hex_bytes(backing_coin.puzzle_hash.to_bytes())),
                amount: backing_coin.amount,
            },
            backing_cat: BackingCatJson {
                asset_id: Hex::new(hex_bytes(asset_id.to_bytes())),
                hidden_puzzle_hash: None,
                lineage_proof: LineageProofJson {
                    parent_parent_coin_info: Hex::new(hex_bytes(
                        parent_parent_coin_info.to_bytes(),
                    )),
                    parent_inner_puzzle_hash: Hex::new(hex_bytes(
                        parent_inner_puzzle_hash.to_bytes(),
                    )),
                    parent_amount,
                },
            },
        },
        underlying_amount: 500,
        strike: StrikeType::Cat {
            asset_id: Hex::new(hex_bytes(asset_id.to_bytes())),
            amount: 250,
        },
        expiry_seconds: 1_700_000_000,
        take_by_seconds: 1_710_000_000,
        premium: premium(),
        launcher_coin: Some(CoinJson {
            parent_coin_info: Hex::new(hex_bytes(launcher_coin.parent_coin_info.to_bytes())),
            puzzle_hash: Hex::new(hex_bytes(launcher_coin.puzzle_hash.to_bytes())),
            amount: launcher_coin.amount,
        }),
        fee_floor: 0,
    };

    Fixture {
        sim,
        maker,
        taker,
        terms,
    }
}

impl Fixture {
    /// The quote under test, derived from the terms the way `quote create` derives it.
    fn quote(&self) -> anyhow::Result<Quote> {
        Ok(Quote::new(self.terms.clone())?)
    }

    /// The bundle an external signer returns: the maker's spends carrying the maker's signature.
    fn signed(&self, quote: &Quote) -> anyhow::Result<SpendBundle> {
        let mut bundle = build_maker_bundle(quote)?;
        bundle.aggregated_signature =
            sign_transaction(&bundle.coin_spends, &[self.maker.sk.clone()])?;

        Ok(bundle)
    }

    /// The artifact a maker publishes.
    fn sealed(&self, quote: &Quote) -> anyhow::Result<SealedOffer> {
        Ok(seal(quote, &self.signed(quote)?, OfferFormat::Offer)?)
    }

    /// The taker's half: parse the published offer, fund the premium, and hand back what a wallet
    /// would submit.
    ///
    /// The offer is parsed through [`Offer::from_spend_bundle`], the *untrusted* path, so the
    /// requested payments come out of the published bundle rather than out of this test.
    fn taken(&self, offer_bundle: &SpendBundle) -> anyhow::Result<(Offer, Outputs, SpendBundle)> {
        let mut allocator = Allocator::new();
        let offer = Offer::from_spend_bundle(&mut allocator, offer_bundle)?;

        let mut ctx = SpendContext::new();
        let mut spends = Spends::new(self.taker.puzzle_hash);
        spends.add(offer.offered_coins().clone());
        spends.add(self.taker.coin);

        let deltas = spends.apply(&mut ctx, &offer.requested_payments().actions())?;
        let keys = IndexMap::from_iter([(self.taker.puzzle_hash, self.taker.pk)]);
        let outputs = spends.finish_with_keys(&mut ctx, &deltas, Relation::AssertConcurrent, &keys)?;

        let coin_spends = ctx.take();
        let signature = sign_transaction(&coin_spends, &[self.taker.sk.clone()])?;

        // `take` concatenates the maker's own spends with the taker's, so the published settlement
        // placeholder — the parent-zero spend that encodes the premium — is dropped: the taker's own
        // settlement coin carries the payment instead. The clone is what lets the caller inspect the
        // parsed offer afterwards.
        let bundle = offer.clone().take(SpendBundle::new(coin_spends, signature));

        Ok((offer, outputs, bundle))
    }
}

#[test]
fn a_quote_can_be_sealed_verified_and_taken() -> anyhow::Result<()> {
    let mut fixture = fixture();
    let quote = fixture.quote()?;

    // The maker's half on its own: three spends, no signature, nothing landable.
    let unsigned = build_maker_bundle(&quote)?;
    assert_eq!(unsigned.coin_spends.len(), 3);
    assert_eq!(unsigned.aggregated_signature, Signature::default());

    let sealed = fixture.sealed(&quote)?;

    // The published bundle is the maker's spends plus exactly one settlement placeholder per
    // requested-payment branch: one, because the premium is a single XCH payment.
    assert_eq!(sealed.spend_bundle.coin_spends.len(), 4);
    let placeholders: Vec<&CoinSpend> = sealed
        .spend_bundle
        .coin_spends
        .iter()
        .filter(|coin_spend| coin_spend.coin.parent_coin_info == Bytes32::default())
        .collect();
    assert_eq!(placeholders.len(), 1);
    assert_eq!(
        placeholders[0].coin.puzzle_hash,
        SETTLEMENT_PAYMENT_HASH.into()
    );

    // A taker checks the offer before taking it. This is the whole reason the sidecar exists, and it
    // also proves the emitted code fences agree with `Quote`: the report carries a quote recomputed
    // from the sidecar's terms, not the caller's value.
    let report = verify(&sealed.spend_bundle, &sealed.sidecar)?;
    assert!(report.unmodeled_conditions.is_empty());
    assert_eq!(report.quote, quote);
    assert_eq!(report.modeled.take_by, fixture.terms.take_by_seconds);

    let (offer, outputs, bundle) = fixture.taken(&sealed.spend_bundle)?;

    // The offer the taker parsed really offers the quoted option, and asks for the premium in XCH
    // under the quote's own nonce.
    assert!(
        offer
            .offered_coins()
            .options
            .contains_key(&quote.launcher_id)
    );
    assert_eq!(offer.requested_payments().xch.len(), 1);
    assert_eq!(offer.requested_payments().xch[0].nonce, quote.nonce);

    fixture.sim.new_transaction(bundle)?;

    // The taker ends up holding the option, owned by its own puzzle hash.
    let option = outputs
        .options
        .get(&Id::Existing(quote.launcher_id))
        .expect("the taker holds the option after taking the offer");

    assert_eq!(option.info.launcher_id, quote.launcher_id);
    assert_eq!(option.info.p2_puzzle_hash, fixture.taker.puzzle_hash);
    assert_eq!(
        option.info.underlying_coin_id,
        quote.underlying_coin.coin_id()
    );
    assert_eq!(
        option.info.underlying_delegated_puzzle_hash,
        quote.info.underlying_delegated_puzzle_hash,
        "the option the taker received commits to the strike and underlying the quote derived"
    );
    assert_eq!(option.coin.amount, 1);
    assert_ne!(option.coin.coin_id(), quote.option_coin.coin_id());

    // ...as the single child of the coin the maker committed, so the option was delivered, not
    // re-minted.
    let children = fixture.sim.children(quote.option_coin.coin_id());
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].coin.coin_id(), option.coin.coin_id());

    // The presigned eve spend landed and was consumed in the same bundle: there is no live eve coin.
    for coin in [quote.option_coin, quote.eve_coin] {
        let state = fixture
            .sim
            .coin_state(coin.coin_id())
            .expect("the coin existed on chain");

        assert!(
            state.spent_height.is_some(),
            "coin {} should have been spent",
            coin.coin_id()
        );
    }

    // The underlying is locked at the option's p2 puzzle and untouched by the sale.
    let lock = fixture
        .sim
        .coin_state(quote.underlying_coin.coin_id())
        .expect("the underlying was locked");

    assert!(lock.spent_height.is_none());
    assert_eq!(lock.coin.puzzle_hash, quote.underlying_p2_puzzle_hash());
    assert_eq!(lock.coin.amount, fixture.terms.underlying_amount);

    // The maker was paid the premium the terms name.
    let premiums = fixture
        .sim
        .unspent_coins(fixture.terms.premium_recipient()?, false);
    assert_eq!(premiums.len(), 1);
    assert_eq!(premiums[0].amount, fixture.terms.premium.amount);

    Ok(())
}

#[test]
fn a_cat_backed_quote_can_be_sealed_and_taken() -> anyhow::Result<()> {
    let mut fixture = cat_fixture();
    let quote = fixture.quote()?;

    // Four spends: the CAT coin, the 1-mojo XCH launcher coin, the launcher coin and the eve option.
    let unsigned = build_maker_bundle(&quote)?;
    assert_eq!(unsigned.coin_spends.len(), 4);

    let launcher_spend = unsigned
        .coin_spends
        .iter()
        .find(|coin_spend| coin_spend.coin == quote.launcher_coin)
        .expect("the bundle spends the launcher coin");
    assert_eq!(
        launcher_spend.coin.puzzle_hash,
        SINGLETON_LAUNCHER_HASH.into()
    );

    let sealed = fixture.sealed(&quote)?;
    assert_eq!(sealed.spend_bundle.coin_spends.len(), 5);

    // The CAT-backed offer verifies, and the launcher's own metadata reads back as the CAT strike the
    // terms name: the CAT-curried settlement puzzle is committed end to end.
    let report = verify(&sealed.spend_bundle, &sealed.sidecar)?;
    assert!(report.unmodeled_conditions.is_empty());
    assert_eq!(
        report.metadata.strike_type,
        OptionType::Cat {
            asset_id: Bytes32::new([5; 32]),
            amount: 250,
        }
    );

    let (offer, outputs, bundle) = fixture.taken(&sealed.spend_bundle)?;
    assert!(
        offer
            .offered_coins()
            .options
            .contains_key(&quote.launcher_id)
    );

    // A CAT-backed quote offers the option and nothing else: the lock and the change belong to the
    // option and the maker, and neither sits at the settlement puzzle.
    assert!(offer.offered_coins().cats.is_empty());
    assert!(offer.offered_coins().xch.is_empty());

    fixture.sim.new_transaction(bundle)?;

    let option = outputs
        .options
        .get(&Id::Existing(quote.launcher_id))
        .expect("the taker holds the option after taking the offer");
    assert_eq!(option.info.p2_puzzle_hash, fixture.taker.puzzle_hash);
    assert_eq!(
        option.info.underlying_delegated_puzzle_hash,
        quote.info.underlying_delegated_puzzle_hash
    );

    // The lock is a CAT coin at the CAT-wrapped p2 puzzle hash, which is a different coin id from the
    // inner puzzle's hash the CAT spend names.
    let lock = fixture
        .sim
        .coin_state(quote.underlying_coin.coin_id())
        .expect("the underlying was locked");

    assert!(lock.spent_height.is_none());
    assert_eq!(lock.coin.puzzle_hash, quote.underlying_coin.puzzle_hash);
    assert_ne!(lock.coin.puzzle_hash, quote.underlying_p2_puzzle_hash());
    assert_eq!(lock.coin.amount, fixture.terms.underlying_amount);

    // The maker keeps the CAT change: 1_000 locked against 500 locked, at the maker's CAT puzzle.
    let asset_id = Bytes32::new([5; 32]);
    let change_puzzle_hash: Bytes32 = CatInfo::new(asset_id, None, fixture.maker.puzzle_hash)
        .puzzle_hash()
        .into();
    let change = fixture.sim.unspent_coins(change_puzzle_hash, false);
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].amount, 500);

    // Both of the maker's own coins are gone, and the taker paid the premium.
    for coin in [
        quote.terms.backing_coin()?,
        quote.terms.launcher_coin()?.expect("launcher coin"),
    ] {
        let state = fixture
            .sim
            .coin_state(coin.coin_id())
            .expect("the coin existed on chain");

        assert!(state.spent_height.is_some(), "coin {}", coin.coin_id());
    }

    let premiums = fixture
        .sim
        .unspent_coins(fixture.terms.premium_recipient()?, false);
    assert_eq!(premiums.len(), 1);
    assert_eq!(premiums[0].amount, fixture.terms.premium.amount);

    Ok(())
}

#[test]
fn the_maker_bundle_alone_is_not_landable() -> anyhow::Result<()> {
    let mut fixture = fixture();
    let quote = fixture.quote()?;

    // No settlement coin is in the bundle, so no puzzle announcement can satisfy the premium
    // assertion: the maker's own coin cannot be spent into a quote without the premium being paid
    // (Verification Note 4). Without this the offer would be a free option for any observer.
    let signed = fixture.signed(&quote)?;
    let error = fixture.sim.new_transaction(signed).unwrap_err();

    assert!(
        matches!(
            error,
            SimulatorError::Validation(ErrorCode::AssertPuzzleAnnouncementFailed)
        ),
        "{error:?}"
    );

    Ok(())
}

#[test]
fn an_offer_lands_only_before_its_take_by() -> anyhow::Result<()> {
    let mut fixture = fixture();
    let take_by = fixture.terms.take_by_seconds;

    let quote = fixture.quote()?;
    let sealed = fixture.sealed(&quote)?;
    let (_, _, bundle) = fixture.taken(&sealed.spend_bundle)?;

    // The deadline is exclusive: at exactly `take_by_seconds` the offer no longer lands, because the
    // condition fails when `take_by <= now` (Verification Note 5). Setting the clock to the deadline
    // rather than past it is what pins that comparison, and why the terms reject a zero take-by.
    //
    // This is exact only because the fixture lands no transaction: the simulator's clock starts at
    // zero and `create_block` advances it by one per transaction, so with nothing submitted the only
    // constraint on the jump is that it is not before the last block's timestamp.
    fixture.sim.set_next_timestamp(take_by)?;
    let error = fixture.sim.new_transaction(bundle).unwrap_err();

    assert!(
        matches!(
            error,
            SimulatorError::Validation(ErrorCode::AssertBeforeSecondsAbsoluteFailed)
        ),
        "{error:?}"
    );

    Ok(())
}

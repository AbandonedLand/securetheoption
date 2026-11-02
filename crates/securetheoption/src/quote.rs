//! The offline precompute chain: every identifier a quote commits to, derived from [`QuoteTerms`].
//!
//! Nothing here talks to a node. A bare [`SpendContext`] — a legal offline allocator — is used only to
//! hash the two allocator-dependent values (the eve option's inner puzzle and the notarized premium
//! payment), then thrown away. The resulting [`Quote`] is pure data: the builder re-derives the same
//! values from the same terms, and `verify` re-derives them again from the sidecar.

use chia_wallet_sdk::chia::puzzle_types::offer::{NotarizedPayment, Payment};
use chia_wallet_sdk::prelude::*;
use chia_wallet_sdk::puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_wallet_sdk::types::{payment_assertion, tree_hash_notarized_payment};

use crate::error::SecError;
use crate::terms::{BackingAsset, LAUNCHER_AMOUNT, QuoteTerms, SINGLETON_AMOUNT};

/// The full derivation chain of one quote, precomputed offline.
///
/// Every field is either an input to a later hash or one of the identifiers FR1 promises, so the
/// builder, the sidecar and the verifier can all start from the same numbers instead of recomputing
/// them differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    /// The terms the quote was derived from: the sidecar's payload.
    pub terms: QuoteTerms,

    /// The coin whose spend creates the launcher coin: the backing coin for an XCH underlying, the
    /// dedicated XCH `launcher_coin` for a CAT underlying.
    pub launcher_parent_coin: Coin,

    /// The `LAUNCHER_AMOUNT`-sized coin at `SINGLETON_LAUNCHER_HASH` that the parent creates.
    pub launcher_coin: Coin,

    /// The launcher id: the option's identity on chain, and the strike payment's nonce.
    pub launcher_id: Bytes32,

    /// The underlying's p2 puzzle: the 1-of-2 MIPS puzzle the lock coin sits at.
    pub underlying: OptionUnderlying,

    /// The coin that locks the underlying until the option is exercised or expires.
    pub underlying_coin: Coin,

    /// The option contract's committed info, including `underlying_delegated_puzzle_hash`.
    pub info: OptionInfo,

    /// The eve option's inner puzzle hash: `(q . ((51 owner SINGLETON_AMOUNT (owner))))`.
    ///
    /// Built the way `OptionLauncher::mint` builds it — a `clvm_quote` of the create-coin conditions —
    /// so the eve coin id this crate precomputes and the eve spend the SDK builds cannot disagree.
    pub eve_p2_puzzle_hash: Bytes32,

    /// The eve option coin, spent inside the presigned bundle. It never lands on chain as a live coin.
    pub eve_coin: Coin,

    /// The offered option coin, delivered with `SETTLEMENT_PAYMENT_HASH` as its inner p2.
    pub option_coin: Coin,

    /// The nonce the premium payment is notarized with, over the offer's cancellable coin ids.
    pub nonce: Bytes32,
}

impl Quote {
    /// Derives the whole chain from validated terms.
    pub fn new(terms: QuoteTerms) -> Result<Self, SecError> {
        terms.validate()?;

        let mut ctx = SpendContext::new();

        let owner: Bytes32 = SETTLEMENT_PAYMENT_HASH.into();
        let backing_coin = terms.backing_coin()?;

        let launcher_parent_coin = match &terms.underlying {
            BackingAsset::Xch { .. } => backing_coin,
            BackingAsset::Cat { .. } => terms.launcher_coin()?.ok_or_else(|| {
                SecError::terms("a CAT backing coin requires an XCH `launcher_coin`")
            })?,
        };

        // `create_early` rather than `new`: the launcher amount is pinned to `LAUNCHER_AMOUNT` and the
        // launcher coin is created by a hand-built spend, not by the launcher's own constructor.
        let (_, launcher) = OptionLauncher::create_early(
            &mut ctx,
            launcher_parent_coin.coin_id(),
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

        let launcher_coin = launcher.launcher().coin();
        let launcher_id = launcher_coin.coin_id();
        let underlying = launcher.underlying();
        let underlying_p2_puzzle_hash = launcher.p2_puzzle_hash();

        // A CAT spend wraps every `create_coin` puzzle hash in the CAT outer puzzle, so the lock coin's
        // id is the wrapped hash even though the spend itself names the inner one.
        let underlying_coin = match terms.backing_cat()? {
            None => Coin::new(
                backing_coin.coin_id(),
                underlying_p2_puzzle_hash,
                terms.underlying_amount,
            ),
            Some(cat) => Coin::new(
                backing_coin.coin_id(),
                CatInfo::new(
                    cat.asset_id,
                    cat.hidden_puzzle_hash,
                    underlying_p2_puzzle_hash,
                )
                .puzzle_hash()
                .into(),
                terms.underlying_amount,
            ),
        };

        let launcher = launcher.with_underlying(underlying_coin.coin_id());
        let info = launcher.info();

        // The eve option's inner puzzle is the `Conditions` list `OptionLauncher::mint` curries; this
        // is the same `clvm_quote` shape, so both hash to the same tree.
        let memos = ctx.hint(owner)?;
        let eve_inner_spend =
            ctx.delegated_spend(Conditions::new().create_coin(owner, SINGLETON_AMOUNT, memos))?;
        let eve_p2_puzzle_hash: Bytes32 = ctx.tree_hash(eve_inner_spend.puzzle).into();

        let (_, eve_option) = launcher.mint_eve(&mut ctx, eve_p2_puzzle_hash)?;
        let eve_coin = eve_option.coin;
        let option_coin = eve_option.child(owner, SINGLETON_AMOUNT).coin;

        let nonce = Offer::nonce(Self::cancellable_coin_ids(&terms)?);

        Ok(Self {
            terms,
            launcher_parent_coin,
            launcher_coin,
            launcher_id,
            underlying,
            underlying_coin,
            info,
            eve_p2_puzzle_hash,
            eve_coin,
            option_coin,
            nonce,
        })
    }

    /// The underlying's p2 puzzle hash, inside any asset layer.
    pub fn underlying_p2_puzzle_hash(&self) -> Bytes32 {
        self.underlying.tree_hash().into()
    }

    /// The option's outer puzzle hash: what a coin holding the option actually reveals.
    pub fn option_puzzle_hash(&self) -> Bytes32 {
        self.info.puzzle_hash().into()
    }

    /// The puzzle hash the premium must be paid to: the settlement puzzle, CAT-wrapped when the
    /// premium asset is a CAT.
    pub fn premium_settlement_puzzle_hash(&self) -> Result<Bytes32, SecError> {
        Ok(match self.terms.premium_asset_id()? {
            None => SETTLEMENT_PAYMENT_HASH.into(),
            Some(asset_id) => CatInfo::new(
                asset_id,
                self.terms.premium_hidden_puzzle_hash()?,
                SETTLEMENT_PAYMENT_HASH.into(),
            )
            .puzzle_hash()
            .into(),
        })
    }

    /// The premium payment, notarized with this quote's nonce.
    ///
    /// A CAT payment carries the recipient as a hint, matching how the SDK notarizes CAT strike
    /// payments; the hint is part of the hash the maker asserts, so it is fixed here once.
    pub fn premium_payment(&self, ctx: &mut SpendContext) -> Result<NotarizedPayment, SecError> {
        let recipient = self.terms.premium_recipient()?;

        let memos = match self.terms.premium_asset_id()? {
            None => Memos::None,
            Some(_) => ctx.hint(recipient)?,
        };

        Ok(NotarizedPayment::new(
            self.nonce,
            vec![Payment::new(recipient, self.terms.premium.amount, memos)],
        ))
    }

    /// The hash of the notarized premium payment: the half of the assertion a taker's settlement
    /// spend announces.
    pub fn premium_payment_hash(&self) -> Result<TreeHash, SecError> {
        let mut ctx = SpendContext::new();
        let payment = self.premium_payment(&mut ctx)?;

        Ok(tree_hash_notarized_payment(&ctx, &payment))
    }

    /// The single `AssertPuzzleAnnouncement` that binds the maker bundle to the premium.
    pub fn premium_assertion(
        &self,
        ctx: &mut SpendContext,
    ) -> Result<AssertPuzzleAnnouncement, SecError> {
        let payment = self.premium_payment(ctx)?;

        Ok(payment_assertion(
            self.premium_settlement_puzzle_hash()?,
            tree_hash_notarized_payment(ctx, &payment),
        ))
    }

    /// The requested payments the offer carries, ready for `Offer::from_input_spend_bundle`.
    pub fn requested_payments(
        &self,
        ctx: &mut SpendContext,
    ) -> Result<RequestedPayments, SecError> {
        let payment = self.premium_payment(ctx)?;
        let mut requested_payments = RequestedPayments::new();

        match self.terms.premium_asset_id()? {
            None => requested_payments.xch.push(payment),
            Some(asset_id) => {
                requested_payments
                    .cats
                    .entry(asset_id)
                    .or_default()
                    .push(payment);
            }
        }

        Ok(requested_payments)
    }

    /// The asset info the offer needs: `to_spend_bundle` re-derives the CAT settlement puzzle from it,
    /// so it must reach `from_input_spend_bundle` unmodified.
    pub fn asset_info(&self) -> Result<AssetInfo, SecError> {
        let mut asset_info = AssetInfo::new();

        if let Some(asset_id) = self.terms.premium_asset_id()? {
            asset_info.insert_cat(
                asset_id,
                CatAssetInfo::new(self.terms.premium_hidden_puzzle_hash()?),
            )?;
        }

        Ok(asset_info)
    }

    /// The coins a taker must spend for the offer to be cancellable: every input the bundle does not
    /// create itself, and therefore exactly the ids `Offer::nonce` hashes.
    ///
    /// For CAT backing that set has two members, but only the backing CAT spend carries the premium
    /// and take-by assertions; the dedicated XCH launcher coin is cancellable without asserting.
    fn cancellable_coin_ids(terms: &QuoteTerms) -> Result<Vec<Bytes32>, SecError> {
        let mut coin_ids = vec![terms.backing_coin()?.coin_id()];

        if let Some(launcher_coin) = terms.launcher_coin()? {
            coin_ids.push(launcher_coin.coin_id());
        }

        Ok(coin_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::{
        BackingCatJson, CoinJson, Hex, LineageProofJson, Premium, PremiumAsset, StrikeType,
    };

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

    fn cat_terms() -> QuoteTerms {
        let (maker_public_key, maker_puzzle_hash) = maker();
        let asset_id = Bytes32::new([5; 32]);
        let backing_puzzle_hash: Bytes32 = CatInfo::new(asset_id, None, maker_puzzle_hash)
            .puzzle_hash()
            .into();

        QuoteTerms {
            maker_public_key,
            creator_puzzle_hash: hex32([9; 32]),
            underlying: BackingAsset::Cat {
                coin: CoinJson {
                    parent_coin_info: hex32([1; 32]),
                    puzzle_hash: hex32(backing_puzzle_hash.to_bytes()),
                    amount: 1_000,
                },
                backing_cat: BackingCatJson {
                    asset_id: hex32(asset_id.to_bytes()),
                    hidden_puzzle_hash: None,
                    lineage_proof: LineageProofJson {
                        parent_parent_coin_info: hex32([2; 32]),
                        parent_inner_puzzle_hash: hex32([3; 32]),
                        parent_amount: 5_000,
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

    /// CAT backing with a CAT premium in an unrelated asset, so an asset-info collision can never be
    /// what a test is accidentally measuring.
    fn cat_premium_terms(hidden_puzzle_hash: Option<[u8; 32]>) -> QuoteTerms {
        let mut terms = cat_terms();

        terms.premium.asset = PremiumAsset::Cat {
            asset_id: hex32([13; 32]),
            hidden_puzzle_hash: hidden_puzzle_hash.map(hex32),
        };

        terms
    }

    #[test]
    fn xch_quote_matches_the_sdk_mint() -> anyhow::Result<()> {
        let terms = xch_terms(501);
        let quote = Quote::new(terms.clone())?;

        let mut ctx = SpendContext::new();
        let owner: Bytes32 = SETTLEMENT_PAYMENT_HASH.into();

        let (_, launcher) = OptionLauncher::create_early(
            &mut ctx,
            terms.backing_coin()?.coin_id(),
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
        assert_eq!(launcher.launcher().coin(), quote.launcher_coin);

        let launcher = launcher.with_underlying(quote.underlying_coin.coin_id());
        let (_, option) = launcher.mint(&mut ctx)?;

        // The option's parent is the eve coin, whose id hashes the eve p2 puzzle, so this also pins
        // `quote.eve_p2_puzzle_hash` against the SDK's own derivation.
        assert_eq!(option.coin, quote.option_coin);
        assert_eq!(option.coin.parent_coin_info, quote.eve_coin.coin_id());

        Ok(())
    }

    #[test]
    fn option_coin_amount_is_odd() -> anyhow::Result<()> {
        for terms in [xch_terms(501), cat_terms()] {
            let quote = Quote::new(terms)?;
            assert_eq!(quote.option_coin.amount % 2, 1);
            assert_eq!(quote.option_coin.amount, SINGLETON_AMOUNT);
        }

        Ok(())
    }

    #[test]
    fn option_coin_sits_at_the_singleton_puzzle_hash() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(501))?;

        assert_eq!(quote.info.launcher_id, quote.launcher_id);
        assert_eq!(
            quote.info.underlying_coin_id,
            quote.underlying_coin.coin_id()
        );
        assert_eq!(
            quote.info.underlying_delegated_puzzle_hash,
            quote.underlying.delegated_puzzle().tree_hash().into()
        );
        assert_eq!(quote.info.p2_puzzle_hash, SETTLEMENT_PAYMENT_HASH.into());
        assert_eq!(quote.option_coin.puzzle_hash, quote.option_puzzle_hash());

        Ok(())
    }

    #[test]
    fn xch_lock_coin_sits_at_the_option_p2() -> anyhow::Result<()> {
        let quote = Quote::new(xch_terms(501))?;

        assert_eq!(
            quote.underlying_coin.puzzle_hash,
            quote.underlying_p2_puzzle_hash()
        );
        assert_eq!(quote.underlying_coin.amount, 500);

        Ok(())
    }

    #[test]
    fn cat_lock_coin_is_wrapped_in_the_cat_puzzle() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let cat = quote.terms.backing_cat()?.expect("CAT backing");

        let expected: Bytes32 = CatInfo::new(
            cat.asset_id,
            cat.hidden_puzzle_hash,
            quote.underlying_p2_puzzle_hash(),
        )
        .puzzle_hash()
        .into();

        assert_eq!(quote.underlying_coin.puzzle_hash, expected);
        assert_ne!(
            quote.underlying_coin.puzzle_hash,
            quote.underlying_p2_puzzle_hash()
        );
        assert_eq!(quote.underlying_coin.amount, 1_000);

        Ok(())
    }

    #[test]
    fn nonce_covers_the_cancellable_coins() -> anyhow::Result<()> {
        let xch = xch_terms(501);
        let quote = Quote::new(xch.clone())?;
        assert_eq!(
            quote.nonce,
            Offer::nonce(vec![xch.backing_coin()?.coin_id()])
        );

        let cat = cat_terms();
        let quote = Quote::new(cat.clone())?;
        assert_eq!(
            quote.nonce,
            Offer::nonce(vec![
                cat.backing_coin()?.coin_id(),
                cat.launcher_coin()?.expect("launcher coin").coin_id(),
            ])
        );

        Ok(())
    }

    #[test]
    fn premium_assertion_matches_the_requested_payments() -> anyhow::Result<()> {
        for terms in [
            xch_terms(501),
            cat_premium_terms(None),
            cat_premium_terms(Some([6; 32])),
        ] {
            let mut ctx = SpendContext::new();
            let quote = Quote::new(terms)?;

            let asset_info = quote.asset_info()?;
            let requested_payments = quote.requested_payments(&mut ctx)?;
            let assertions = requested_payments.assertions(&mut ctx, &asset_info)?;

            assert_eq!(assertions, vec![quote.premium_assertion(&mut ctx)?]);
        }

        Ok(())
    }

    #[test]
    fn premium_settlement_puzzle_follows_the_asset() -> anyhow::Result<()> {
        let xch = Quote::new(xch_terms(501))?;
        assert_eq!(
            xch.premium_settlement_puzzle_hash()?,
            SETTLEMENT_PAYMENT_HASH.into()
        );

        let plain = Quote::new(cat_premium_terms(None))?;
        let revocable = Quote::new(cat_premium_terms(Some([6; 32])))?;

        assert_eq!(
            plain.premium_settlement_puzzle_hash()?,
            CatInfo::new(Bytes32::new([13; 32]), None, SETTLEMENT_PAYMENT_HASH.into())
                .puzzle_hash()
                .into()
        );
        assert_ne!(
            plain.premium_settlement_puzzle_hash()?,
            revocable.premium_settlement_puzzle_hash()?
        );

        Ok(())
    }

    #[test]
    fn premium_payment_hash_is_stable() -> anyhow::Result<()> {
        let quote = Quote::new(cat_premium_terms(Some([6; 32])))?;

        assert_eq!(quote.premium_payment_hash()?, quote.premium_payment_hash()?);

        let mut ctx = SpendContext::new();
        let payment = quote.premium_payment(&mut ctx)?;
        assert_eq!(
            quote.premium_payment_hash()?,
            tree_hash_notarized_payment(&ctx, &payment)
        );

        Ok(())
    }

    #[test]
    fn quote_is_deterministic() -> anyhow::Result<()> {
        let terms = cat_terms();

        assert_eq!(Quote::new(terms.clone())?, Quote::new(terms)?);

        Ok(())
    }
}

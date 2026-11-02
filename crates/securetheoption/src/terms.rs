//! The plaintext terms of a quote: the JSON document the CLI reads and the sidecar writes.
//!
//! Every identifier on the wire is a `0x`-prefixed hex string so a terms file stays hand-editable.
//! The typed accessors parse those strings into the SDK types the builder needs, and
//! [`QuoteTerms::validate`] uses them to reject inconsistent input before any hashing happens.

use chia_wallet_sdk::chia::puzzle_types::LineageProof;
use chia_wallet_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::SecError;

/// The amount of the launcher coin, pinned to 0 so a quote's hashes never depend on how the launcher
/// is funded. The SDK's convenience constructor would hardcode 1 instead, which changes every
/// downstream hash.
pub const LAUNCHER_AMOUNT: u64 = 0;

/// The amount of the option singleton, and of the eve coin the launcher creates.
///
/// Must be odd: [`OptionContract::parse_child`] only recognises a child whose `create_coin` amount is
/// odd, so an even amount would silently drop the option from the offer.
pub const SINGLETON_AMOUNT: u64 = 1;

/// A `0x`-prefixed hex string: the on-the-wire form of every id in a terms file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hex(pub String);

impl Hex {
    /// Wraps a string, which may or may not carry a `0x` prefix.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Decodes the string into exactly `N` bytes.
    pub fn bytes<const N: usize>(&self, field: &'static str) -> Result<[u8; N], SecError> {
        let trimmed = self
            .0
            .strip_prefix("0x")
            .or_else(|| self.0.strip_prefix("0X"))
            .unwrap_or(self.0.as_str());

        let decoded = hex::decode(trimmed).map_err(|error| SecError::hex(field, error.to_string()))?;
        let len = decoded.len();

        decoded
            .try_into()
            .map_err(|_: Vec<u8>| SecError::hex(field, format!("expected {N} bytes, got {len}")))
    }

    /// Decodes the string into a 32-byte hash.
    pub fn bytes32(&self, field: &'static str) -> Result<Bytes32, SecError> {
        Ok(Bytes32::new(self.bytes::<32>(field)?))
    }

    /// Decodes the string into a BLS G1 public key, rejecting the point at infinity.
    pub fn public_key(&self, field: &'static str) -> Result<PublicKey, SecError> {
        let bytes = self.bytes::<48>(field)?;
        let public_key = PublicKey::from_bytes(&bytes)
            .map_err(|error| SecError::hex(field, error.to_string()))?;

        if public_key.is_inf() {
            return Err(SecError::hex(field, "the point at infinity is not a usable key"));
        }

        Ok(public_key)
    }
}

/// A coin in its JSON form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinJson {
    /// Hex parent coin id.
    pub parent_coin_info: Hex,
    /// Hex puzzle hash.
    pub puzzle_hash: Hex,
    /// Amount in mojos, or in the asset's base units for a CAT.
    pub amount: u64,
}

impl CoinJson {
    /// Parses the coin.
    pub fn coin(&self) -> Result<Coin, SecError> {
        Ok(Coin::new(
            self.parent_coin_info.bytes32("coin.parent_coin_info")?,
            self.puzzle_hash.bytes32("coin.puzzle_hash")?,
            self.amount,
        ))
    }
}

/// A CAT's lineage proof, needed to spend it and impossible to derive offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageProofJson {
    /// The parent's parent coin id.
    pub parent_parent_coin_info: Hex,
    /// The parent's inner puzzle hash.
    pub parent_inner_puzzle_hash: Hex,
    /// The parent's amount.
    pub parent_amount: u64,
}

impl LineageProofJson {
    /// Parses the proof.
    pub fn lineage_proof(&self) -> Result<LineageProof, SecError> {
        Ok(LineageProof {
            parent_parent_coin_info: self
                .parent_parent_coin_info
                .bytes32("underlying.backing_cat.lineage_proof.parent_parent_coin_info")?,
            parent_inner_puzzle_hash: self
                .parent_inner_puzzle_hash
                .bytes32("underlying.backing_cat.lineage_proof.parent_inner_puzzle_hash")?,
            parent_amount: self.parent_amount,
        })
    }
}

/// The CAT-only half of a backing coin's terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackingCatJson {
    /// Hex asset id (the TAIL program hash).
    pub asset_id: Hex,
    /// Present only for revocable CATs, which [`QuoteTerms::validate`] rejects.
    #[serde(default)]
    pub hidden_puzzle_hash: Option<Hex>,
    /// The lineage proof the CAT spend must carry.
    pub lineage_proof: LineageProofJson,
}

/// What the maker commits as the option's underlying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackingAsset {
    /// An XCH coin held at the maker's standard-layer puzzle hash.
    Xch {
        /// The XCH coin to spend.
        coin: CoinJson,
    },

    /// A CAT coin. Because a singleton launcher is structurally XCH-only — the launcher coin's puzzle
    /// hash must be `SINGLETON_LAUNCHER_HASH` — a CAT-underwritten quote also needs a separate XCH
    /// `launcher_coin`, and the launcher id it produces is a hash input, not merely a value input.
    Cat {
        /// The CAT coin to spend.
        coin: CoinJson,
        /// The CAT-specific terms.
        backing_cat: BackingCatJson,
    },
}

/// The strike asset and amount the option can be exercised for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StrikeType {
    /// An XCH strike, paid to the creator's puzzle hash.
    Xch {
        /// Strike amount in mojos.
        amount: u64,
    },
    /// A non-revocable CAT strike, paid to the creator's puzzle hash.
    Cat {
        /// Hex asset id.
        asset_id: Hex,
        /// Strike amount in the asset's base units.
        amount: u64,
    },
    /// Recognised so the shape can be named, then rejected by [`QuoteTerms::strike_type`]: a
    /// revocable CAT strike changes the settlement puzzle in ways this tool does not model.
    RevocableCat {
        /// Hex asset id.
        asset_id: Hex,
        /// Hex hidden puzzle hash.
        hidden_puzzle_hash: Hex,
        /// Strike amount in the asset's base units.
        amount: u64,
    },
    /// Recognised so the shape can be named, then rejected by [`QuoteTerms::strike_type`].
    Nft {
        /// Hex launcher id of the settlement NFT.
        launcher_id: Hex,
        /// Hex settlement puzzle hash.
        settlement_puzzle_hash: Hex,
        /// Strike amount.
        amount: u64,
    },
}

impl StrikeType {
    /// The strike amount, regardless of asset.
    pub fn amount(&self) -> u64 {
        match self {
            Self::Xch { amount }
            | Self::Cat { amount, .. }
            | Self::RevocableCat { amount, .. }
            | Self::Nft { amount, .. } => *amount,
        }
    }

    /// The wire name of the strike kind, used in the rejection message.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Xch { .. } => "xch",
            Self::Cat { .. } => "cat",
            Self::RevocableCat { .. } => "revocable_cat",
            Self::Nft { .. } => "nft",
        }
    }
}

/// The asset the taker pays the premium in. Independent of the strike and the underlying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PremiumAsset {
    /// The premium is paid in XCH, settled against `SETTLEMENT_PAYMENT_HASH`.
    Xch,
    /// The premium is paid in a CAT, settled against the CAT-curried settlement puzzle. Revocable and
    /// non-revocable CATs of one asset id settle against different puzzles, hence the hidden hash.
    Cat {
        /// Hex asset id.
        asset_id: Hex,
        /// Present for revocable CATs.
        #[serde(default)]
        hidden_puzzle_hash: Option<Hex>,
    },
}

/// The premium the taker must pay for the maker's bundle to be landable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Premium {
    /// Hex puzzle hash that receives the premium.
    pub recipient_puzzle_hash: Hex,
    /// Premium amount.
    pub amount: u64,
    /// Premium asset.
    pub asset: PremiumAsset,
}

/// The parsed form of a CAT backing coin.
#[derive(Debug, Clone, Copy)]
pub struct BackingCat {
    /// The TAIL program hash.
    pub asset_id: Bytes32,
    /// Always `None` for the supported subset.
    pub hidden_puzzle_hash: Option<Bytes32>,
    /// The lineage proof the CAT spend must carry.
    pub lineage_proof: LineageProof,
}

/// The full set of maker terms for one quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteTerms {
    /// Hex BLS public key controlling the maker's standard-layer coins.
    pub maker_public_key: Hex,
    /// Hex puzzle hash that receives the underlying on exercise and the strike at expiry.
    pub creator_puzzle_hash: Hex,
    /// The coin and asset the maker commits.
    pub underlying: BackingAsset,
    /// How much of the underlying asset the option locks.
    pub underlying_amount: u64,
    /// The strike asset and amount.
    pub strike: StrikeType,
    /// The option's expiry, in absolute seconds. Committed into the hashes; changing it is a re-mint.
    pub expiry_seconds: u64,
    /// The absolute-seconds deadline after which the offer cannot land. Not committed into any hash.
    pub take_by_seconds: u64,
    /// The premium the taker pays.
    pub premium: Premium,
    /// The XCH coin that funds the launcher. Required for, and only valid for, CAT backing coins.
    #[serde(default)]
    pub launcher_coin: Option<CoinJson>,
    /// Optional `RESERVE_FEE` floor the taker must pay.
    #[serde(default)]
    pub fee_floor: u64,
}

impl QuoteTerms {
    /// Parses the maker's BLS public key.
    pub fn maker_public_key(&self) -> Result<PublicKey, SecError> {
        self.maker_public_key.public_key("maker_public_key")
    }

    /// The maker's standard-layer puzzle hash: where the backing coin must live and where change goes.
    pub fn maker_puzzle_hash(&self) -> Result<Bytes32, SecError> {
        Ok(StandardLayer::new(self.maker_public_key()?).tree_hash().into())
    }

    /// Parses the creator puzzle hash.
    pub fn creator_puzzle_hash(&self) -> Result<Bytes32, SecError> {
        self.creator_puzzle_hash.bytes32("creator_puzzle_hash")
    }

    /// Parses the backing coin.
    pub fn backing_coin(&self) -> Result<Coin, SecError> {
        match &self.underlying {
            BackingAsset::Xch { coin } | BackingAsset::Cat { coin, .. } => coin.coin(),
        }
    }

    /// Parses the optional launcher-funding coin.
    pub fn launcher_coin(&self) -> Result<Option<Coin>, SecError> {
        self.launcher_coin.as_ref().map(CoinJson::coin).transpose()
    }

    /// The coin whose spend creates the launcher coin, and therefore determines the launcher id.
    pub fn launcher_parent_coin_id(&self) -> Result<Bytes32, SecError> {
        match &self.underlying {
            BackingAsset::Xch { coin } => Ok(coin.coin()?.coin_id()),
            BackingAsset::Cat { .. } => {
                let launcher = self.launcher_coin()?.ok_or_else(|| {
                    SecError::terms(
                        "a CAT backing coin requires `launcher_coin`: the launcher is XCH-only, and \
                         its id is a hash input to every option id",
                    )
                })?;

                Ok(launcher.coin_id())
            }
        }
    }

    /// Parses the strike into the SDK's [`OptionType`], rejecting unsupported variants.
    pub fn strike_type(&self) -> Result<OptionType, SecError> {
        match &self.strike {
            StrikeType::Xch { amount } => Ok(OptionType::Xch { amount: *amount }),
            StrikeType::Cat { asset_id, amount } => Ok(OptionType::Cat {
                asset_id: asset_id.bytes32("strike.asset_id")?,
                amount: *amount,
            }),
            unsupported => Err(SecError::UnsupportedStrike(unsupported.kind().to_string())),
        }
    }

    /// Parses the CAT-only backing fields, rejecting revocable CAT backing coins.
    pub fn backing_cat(&self) -> Result<Option<BackingCat>, SecError> {
        let BackingAsset::Cat { backing_cat, .. } = &self.underlying else {
            return Ok(None);
        };

        let hidden_puzzle_hash = backing_cat
            .hidden_puzzle_hash
            .as_ref()
            .map(|hidden| hidden.bytes32("underlying.backing_cat.hidden_puzzle_hash"))
            .transpose()?;

        if hidden_puzzle_hash.is_some() {
            return Err(SecError::UnsupportedRevocableCat);
        }

        Ok(Some(BackingCat {
            asset_id: backing_cat
                .asset_id
                .bytes32("underlying.backing_cat.asset_id")?,
            hidden_puzzle_hash,
            lineage_proof: backing_cat.lineage_proof.lineage_proof()?,
        }))
    }

    /// `None` for an XCH premium, otherwise the CAT asset id.
    pub fn premium_asset_id(&self) -> Result<Option<Bytes32>, SecError> {
        match &self.premium.asset {
            PremiumAsset::Xch => Ok(None),
            PremiumAsset::Cat { asset_id, .. } => {
                Ok(Some(asset_id.bytes32("premium.asset.asset_id")?))
            }
        }
    }

    /// The premium CAT's hidden puzzle hash, which selects the settlement puzzle it must be paid to.
    pub fn premium_hidden_puzzle_hash(&self) -> Result<Option<Bytes32>, SecError> {
        match &self.premium.asset {
            PremiumAsset::Xch => Ok(None),
            PremiumAsset::Cat {
                hidden_puzzle_hash,
                ..
            } => hidden_puzzle_hash
                .as_ref()
                .map(|hidden| hidden.bytes32("premium.asset.hidden_puzzle_hash"))
                .transpose(),
        }
    }

    /// Parses the premium recipient puzzle hash.
    pub fn premium_recipient(&self) -> Result<Bytes32, SecError> {
        self.premium
            .recipient_puzzle_hash
            .bytes32("premium.recipient_puzzle_hash")
    }

    /// Rejects terms that cannot produce a landable, self-consistent quote.
    ///
    /// Nothing here hashes: it is arithmetic and asset plumbing only, so a bad terms file fails before
    /// any CLVM is built.
    pub fn validate(&self) -> Result<(), SecError> {
        let maker_puzzle_hash = self.maker_puzzle_hash()?;
        let creator_puzzle_hash = self.creator_puzzle_hash()?;
        let backing_coin = self.backing_coin()?;

        self.strike_type()?;
        self.premium_asset_id()?;
        self.premium_hidden_puzzle_hash()?;
        self.premium_recipient()?;

        if creator_puzzle_hash == Bytes32::default() {
            return Err(SecError::terms("`creator_puzzle_hash` must not be zero"));
        }

        if self.underlying_amount == 0 {
            return Err(SecError::terms("`underlying_amount` must be greater than zero"));
        }

        if self.strike.amount() == 0 {
            return Err(SecError::terms("the strike amount must be greater than zero"));
        }

        if self.expiry_seconds == 0 {
            return Err(SecError::terms("`expiry_seconds` must be greater than zero"));
        }

        if self.take_by_seconds == 0 {
            return Err(SecError::terms(
                "`take_by_seconds` must be greater than zero: zero trips \
                 `ImpossibleSecondsAbsoluteConstraints` on a real node",
            ));
        }

        match &self.underlying {
            BackingAsset::Xch { .. } => self.validate_xch(&backing_coin, maker_puzzle_hash),
            BackingAsset::Cat { .. } => self.validate_cat(&backing_coin, maker_puzzle_hash),
        }
    }

    fn validate_xch(&self, backing_coin: &Coin, maker_puzzle_hash: Bytes32) -> Result<(), SecError> {
        if backing_coin.puzzle_hash != maker_puzzle_hash {
            return Err(SecError::terms(format!(
                "the XCH backing coin's puzzle hash {} is not the maker's standard-layer puzzle \
                 hash {maker_puzzle_hash} derived from `maker_public_key`",
                backing_coin.puzzle_hash
            )));
        }

        if self.launcher_coin.is_some() {
            return Err(SecError::terms(
                "`launcher_coin` is only valid for CAT backing coins: an XCH backing coin funds the \
                 launcher itself",
            ));
        }

        // The 0-amount launcher coin's spend creates a `SINGLETON_AMOUNT` singleton, so the backing
        // coin has to provide that mojo as well as the lock.
        let required = self
            .underlying_amount
            .checked_add(SINGLETON_AMOUNT)
            .ok_or_else(|| SecError::terms("`underlying_amount` overflows the u64 range"))?;

        if backing_coin.amount < required {
            return Err(SecError::terms(format!(
                "the XCH backing coin holds {} mojos but the quote needs {required}: {underlying} \
                 for the underlying lock plus {singleton} for the option singleton",
                backing_coin.amount,
                underlying = self.underlying_amount,
                singleton = SINGLETON_AMOUNT
            )));
        }

        Ok(())
    }

    fn validate_cat(&self, backing_coin: &Coin, maker_puzzle_hash: Bytes32) -> Result<(), SecError> {
        let cat = self
            .backing_cat()?
            .ok_or_else(|| SecError::terms("a CAT backing coin is required here"))?;

        let expected_puzzle_hash: Bytes32 =
            CatInfo::new(cat.asset_id, cat.hidden_puzzle_hash, maker_puzzle_hash)
                .puzzle_hash()
                .into();

        if backing_coin.puzzle_hash != expected_puzzle_hash {
            return Err(SecError::terms(format!(
                "the CAT backing coin's puzzle hash {} is not {expected_puzzle_hash}, the CAT puzzle \
                 hash of `underlying.backing_cat.asset_id` committed to the maker's standard-layer \
                 puzzle hash",
                backing_coin.puzzle_hash
            )));
        }

        if backing_coin.amount < self.underlying_amount {
            return Err(SecError::terms(format!(
                "the CAT backing coin holds {} but the quote locks {}",
                backing_coin.amount, self.underlying_amount
            )));
        }

        let launcher = self
            .launcher_coin()?
            .ok_or_else(|| SecError::terms("a CAT backing coin requires an XCH `launcher_coin`"))?;

        if launcher.puzzle_hash != maker_puzzle_hash {
            return Err(SecError::terms(format!(
                "`launcher_coin` must sit at the maker's standard-layer puzzle hash \
                 {maker_puzzle_hash}, not {}",
                launcher.puzzle_hash
            )));
        }

        // The launcher coin is spent by `SINGLETON_LAUNCHER`, which creates exactly one coin of
        // `SINGLETON_AMOUNT` and cannot make change. Any surplus would burn as fee.
        if launcher.amount != SINGLETON_AMOUNT {
            return Err(SecError::terms(format!(
                "`launcher_coin` must hold exactly {SINGLETON_AMOUNT} mojo, not {}: the launcher \
                 spend can only create the singleton and cannot return change",
                launcher.amount
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn valid_terms_validate() -> anyhow::Result<()> {
        xch_terms(501).validate()?;
        cat_terms().validate()?;
        Ok(())
    }

    #[test]
    fn xch_terms_reserve_the_option_singleton() -> anyhow::Result<()> {
        let error = xch_terms(500).validate().unwrap_err();
        assert!(error.to_string().contains("option singleton"), "{error}");
        Ok(())
    }

    #[test]
    fn xch_terms_reject_a_launcher_coin() -> anyhow::Result<()> {
        let mut terms = xch_terms(501);
        terms.launcher_coin = cat_terms().launcher_coin;
        let error = terms.validate().unwrap_err();
        assert!(error.to_string().contains("only valid for CAT"), "{error}");
        Ok(())
    }

    #[test]
    fn cat_terms_require_a_launcher_coin() -> anyhow::Result<()> {
        let mut terms = cat_terms();
        terms.launcher_coin = None;
        let error = terms.validate().unwrap_err();
        assert!(error.to_string().contains("launcher_coin"), "{error}");
        Ok(())
    }

    #[test]
    fn cat_terms_require_a_one_mojo_launcher_coin() -> anyhow::Result<()> {
        let mut terms = cat_terms();
        terms.launcher_coin.as_mut().expect("launcher").amount = 2;
        let error = terms.validate().unwrap_err();
        assert!(error.to_string().contains("cannot return change"), "{error}");
        Ok(())
    }

    #[test]
    fn revocable_cat_backing_is_rejected() -> anyhow::Result<()> {
        let mut terms = cat_terms();
        let BackingAsset::Cat { backing_cat, .. } = &mut terms.underlying else {
            panic!("expected a CAT backing coin");
        };
        backing_cat.hidden_puzzle_hash = Some(hex32([6; 32]));

        assert!(matches!(
            terms.validate(),
            Err(SecError::UnsupportedRevocableCat)
        ));
        Ok(())
    }

    #[test]
    fn unsupported_strikes_are_named() -> anyhow::Result<()> {
        for (strike, kind) in [
            (
                StrikeType::RevocableCat {
                    asset_id: hex32([5; 32]),
                    hidden_puzzle_hash: hex32([6; 32]),
                    amount: 1,
                },
                "revocable_cat",
            ),
            (
                StrikeType::Nft {
                    launcher_id: hex32([7; 32]),
                    settlement_puzzle_hash: hex32([8; 32]),
                    amount: 1,
                },
                "nft",
            ),
        ] {
            let mut terms = xch_terms(501);
            terms.strike = strike;
            let error = terms.validate().unwrap_err();
            assert!(
                matches!(&error, SecError::UnsupportedStrike(name) if name == kind),
                "{error}"
            );
        }
        Ok(())
    }

    #[test]
    fn zero_take_by_is_rejected() -> anyhow::Result<()> {
        let mut terms = xch_terms(501);
        terms.take_by_seconds = 0;
        let error = terms.validate().unwrap_err();
        assert!(error.to_string().contains("take_by_seconds"), "{error}");
        Ok(())
    }

    #[test]
    fn malformed_hex_names_the_field() -> anyhow::Result<()> {
        let mut terms = xch_terms(501);
        terms.creator_puzzle_hash = Hex("0xnothex".to_string());
        let error = terms.validate().unwrap_err();
        assert!(error.to_string().contains("creator_puzzle_hash"), "{error}");
        Ok(())
    }

    #[test]
    fn terms_round_trip_through_json() -> anyhow::Result<()> {
        for terms in [xch_terms(501), cat_terms()] {
            let json = serde_json::to_string_pretty(&terms)?;
            let round_trip: QuoteTerms = serde_json::from_str(&json)?;
            assert_eq!(round_trip, terms);
            round_trip.validate()?;
        }
        Ok(())
    }
}

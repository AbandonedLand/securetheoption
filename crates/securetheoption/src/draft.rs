//! The maker's draft terms: the document a non-technical maker writes, and the accessors that turn
//! its human units into the base units [`QuoteTerms`](crate::terms::QuoteTerms) needs.
//!
//! Only the scalars that carry a unit differ from resolved terms. [`XchAmount`] reads a decimal XCH
//! string and scales it to mojos exactly, [`Party`] reads either a bech32m address or a `0x` puzzle
//! hash, and [`Moment`] reads a duration, a calendar instant or raw seconds. All three are transparent
//! newtypes over the string the maker wrote, parsed by an accessor that names its field, so a typo is
//! reported against the field the maker can see instead of surfacing as a serde error with no context.
//!
//! Every accessor here is pure: no I/O, no node, and no clock read — the one accessor whose input is
//! relative, [`Moment::seconds`], takes the clock as a parameter.

use chia_wallet_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::SecError;
use crate::terms::{BackingAsset, BackingCatJson, CoinJson, Hex, PremiumAsset, StrikeType};

/// Mojos per XCH: the asset's base unit is 10^-12.
pub const MOJOS_PER_XCH: u64 = 1_000_000_000_000;

/// The whole-XCH part of the largest amount a `u64` of mojos can hold.
const MAX_XCH_WHOLE: u64 = u64::MAX / MOJOS_PER_XCH;

/// The fractional part of that same maximum, in mojos, rendered with twelve digits.
const MAX_XCH_FRACTION: u64 = u64::MAX % MOJOS_PER_XCH;

/// The number of decimal places an XCH amount may carry: one per mojo.
const XCH_DECIMALS: usize = 12;

/// A draft field failed to parse.
///
/// Every scalar failure that is not itself a hex decoding failure reports through `InvalidTerms`,
/// because a computed field name cannot use [`SecError::Hex`] — its `field` is `&'static str`. The one
/// hex path, a `0x`-prefixed [`Party`], keeps the hex wording it has earned: there the value really is
/// hex, and "invalid hex in `premium.recipient`: expected 32 bytes, got 31" is the message a maker
/// needs.
fn invalid(field: &'static str, message: impl Into<String>) -> SecError {
    SecError::terms(format!("`{field}`: {}", message.into()))
}

/// A decimal XCH amount, exactly as the maker wrote it: `"0.5"`, `"1"`, `"1.000000000001"`.
///
/// XCH is the only asset with a decimal form here. A CAT has no canonical decimal scale, so CAT
/// amounts stay raw base units in the draft; only XCH amounts are scaled.
///
/// [`XchAmount::mojos`] parses the string with integer arithmetic alone. Going through an `f64` would
/// be exactly the rounding the rest of this crate refuses to do.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct XchAmount(pub String);

impl XchAmount {
    /// Wraps a string the maker wrote.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Scales the decimal to mojos, exactly.
    ///
    /// Accepted: an optional fractional part with at most twelve digits, no sign, no exponent, no
    /// grouping separator. Rejected: everything else, including a bare JSON number, which serde
    /// refuses before this is reached.
    pub fn mojos(&self, field: &'static str) -> Result<u64, SecError> {
        let text = self.0.trim();

        if text.is_empty() {
            return Err(invalid(
                field,
                "expected a decimal XCH amount such as `0.5` or `1`",
            ));
        }

        let (whole, fraction) = match text.split_once('.') {
            Some((whole, fraction)) => (whole, fraction),
            None => (text, ""),
        };

        if !whole.chars().all(|ch| ch.is_ascii_digit())
            || !fraction.chars().all(|ch| ch.is_ascii_digit())
        {
            return Err(invalid(
                field,
                format!(
                    "`{text}` is not a decimal XCH amount: digits and at most one `.` are accepted, \
                     with no sign and no exponent"
                ),
            ));
        }

        if whole.is_empty() {
            return Err(invalid(
                field,
                format!("`{text}` has no whole part: write `0.5` rather than `.5`"),
            ));
        }

        if text.contains('.') && fraction.is_empty() {
            return Err(invalid(
                field,
                format!("`{text}` has a `.` and no fraction digits"),
            ));
        }

        if fraction.len() > XCH_DECIMALS {
            return Err(invalid(
                field,
                format!(
                    "`{text}` carries {} fractional digits; mojos are 10^-{XCH_DECIMALS}, so at most \
                     {XCH_DECIMALS} are exact",
                    fraction.len()
                ),
            ));
        }

        let range = format!(
            "`{text}` is beyond the u64 mojo range: at most {MAX_XCH_WHOLE}.{MAX_XCH_FRACTION:012} \
             XCH can be expressed"
        );

        let whole: u64 = whole.parse().map_err(|_| invalid(field, range.clone()))?;
        let mut padded = String::from(fraction);

        while padded.len() < XCH_DECIMALS {
            padded.push('0');
        }

        let fraction: u64 = padded.parse().map_err(|_| invalid(field, range.clone()))?;

        whole
            .checked_mul(MOJOS_PER_XCH)
            .and_then(|scaled| scaled.checked_add(fraction))
            .ok_or_else(|| invalid(field, range))
    }
}

/// Where a payment or a payout goes: a bech32m address, or a `0x` puzzle hash.
///
/// Accepting an address is the whole point — a maker reads `xch1…` off their wallet, never a 32-byte
/// hash. The prefix is checked rather than ignored: [`Address::decode`] accepts any human-readable
/// part, so a `txch1…` address would otherwise slip into a mainnet quote without a word.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Party(pub String);

impl Party {
    /// Wraps a string the maker wrote.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Decodes the party into the puzzle hash it names.
    ///
    /// A `0x` string is read as hex; anything else has to be a bech32m address whose prefix matches
    /// `prefix` (`"xch"` on mainnet, `"txch"` on testnet11). A bare hex hash without the `0x` marker is
    /// rejected, so the two forms stay distinguishable.
    pub fn puzzle_hash(&self, prefix: &str, field: &'static str) -> Result<Bytes32, SecError> {
        let text = self.0.trim();

        if text.is_empty() {
            return Err(invalid(
                field,
                "expected a bech32m address such as `xch1…`, or a `0x` puzzle hash",
            ));
        }

        if text.starts_with("0x") || text.starts_with("0X") {
            return Hex::new(text).bytes32(field);
        }

        let address = Address::decode(text).map_err(|error| {
            invalid(field, format!("`{text}` is not a bech32m address: {error}"))
        })?;

        address
            .expect_prefix(prefix)
            .map_err(|error| invalid(field, format!("`{text}`: {error}")))
    }
}

/// Seconds in a minute, an hour and a day: the units a relative [`Moment`] may use.
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;

/// The three shapes a [`Moment`] accepts, quoted by every rejection so the answer is in the error.
const MOMENT_FORMS: &str = "expected a duration such as `30d` (in `s`, `m`, `h` or `d`), an RFC3339 \
     instant such as `2026-12-15T00:00:00Z`, or absolute unix seconds";

/// A deadline, written the way a maker thinks about it: `"30d"`, `"2026-12-15T00:00:00Z"`, `"1797292800"`.
///
/// A duration is relative to a clock the caller supplies; an RFC3339 instant and raw seconds are
/// absolute. [`Moment::seconds`] resolves all three to the absolute seconds a [`QuoteTerms`] carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Moment(pub String);

impl Moment {
    /// Wraps a string the maker wrote.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Resolves the deadline to absolute unix seconds.
    ///
    /// `now_seconds` is the clock a relative form (`30d`) is measured from. The library never reads a
    /// clock of its own, so a duration against `now_seconds == 0` is refused rather than silently
    /// landing in 1970: a caller that offers a relative form has to say what it is relative to.
    ///
    /// The calendar conversion is owned integer arithmetic — no dependency, no `f64`, no time zone
    /// database. Only UTC instants are accepted, and a pre-1970 instant is rejected because absolute
    /// seconds here are a `u64`.
    pub fn seconds(&self, now_seconds: u64, field: &'static str) -> Result<u64, SecError> {
        let text = self.0.trim();

        if text.is_empty() {
            return Err(invalid(field, MOMENT_FORMS));
        }

        if text.bytes().all(|byte| byte.is_ascii_digit()) {
            return text
                .parse()
                .map_err(|_| invalid(field, format!("`{text}` is beyond the u64 second range")));
        }

        // `text.len() - 1` is a byte offset, so a multi-byte character at that index would panic
        // instead of reporting. Every accepted form is ASCII, so refuse the rest before splitting.
        if !text.is_ascii() {
            return Err(invalid(
                field,
                format!("`{text}` contains a non-ASCII character: {MOMENT_FORMS}"),
            ));
        }

        let (digits, unit) = text.split_at(text.len() - 1);
        let unit_seconds = match unit {
            "s" => Some(1),
            "m" => Some(SECONDS_PER_MINUTE),
            "h" => Some(SECONDS_PER_HOUR),
            "d" => Some(SECONDS_PER_DAY),
            _ => None,
        };

        if let Some(unit_seconds) = unit_seconds {
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid(
                    field,
                    format!(
                        "`{text}` is not a duration: a duration is a whole number of seconds, \
                         minutes, hours or days followed by `s`, `m`, `h` or `d`, such as `30d`"
                    ),
                ));
            }

            if now_seconds == 0 {
                return Err(invalid(
                    field,
                    format!(
                        "`{text}` is relative but no clock was supplied: pass `--now <unix seconds>` \
                         or write an absolute instant such as `2026-12-15T00:00:00Z`"
                    ),
                ));
            }

            let count: u64 = digits
                .parse()
                .map_err(|_| invalid(field, format!("`{text}` is beyond the u64 second range")))?;

            return count
                .checked_mul(unit_seconds)
                .and_then(|seconds| seconds.checked_add(now_seconds))
                .ok_or_else(|| {
                    invalid(
                        field,
                        format!("`{text}` from now is beyond the u64 second range"),
                    )
                });
        }

        if text.contains('-') || text.contains('T') {
            return parse_rfc3339_utc(text).map_err(|reason| invalid(field, reason));
        }

        Err(invalid(
            field,
            format!("`{text}` is not a deadline: {MOMENT_FORMS}"),
        ))
    }
}

/// Renders absolute seconds as the `YYYY-MM-DDTHH:MM:SSZ` instant [`Moment::seconds`] accepts, so a
/// preview can show a deadline in the same form the maker wrote it.
///
/// Values past `9999-12-31T23:59:59Z` render with a wider year and then no longer parse back; every
/// deadline a draft can express is far below that.
pub fn rfc3339(seconds: u64) -> String {
    let (year, month, day) = civil_from_days((seconds / SECONDS_PER_DAY) as i64);
    let rest = seconds % SECONDS_PER_DAY;
    let hour = rest / SECONDS_PER_HOUR;
    let minute = (rest % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
    let second = rest % SECONDS_PER_MINUTE;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parses a strict RFC3339 UTC instant, returning the reason it was refused.
fn parse_rfc3339_utc(text: &str) -> Result<u64, String> {
    const SHAPE: &str = "expected an RFC3339 UTC instant of exactly `YYYY-MM-DDTHH:MM:SSZ`";

    let bytes = text.as_bytes();

    if !text.is_ascii() {
        return Err(format!("`{text}` contains a non-ASCII character: {SHAPE}"));
    }

    if bytes.len() != 20 {
        return Err(format!("`{text}` has {} characters: {SHAPE}", bytes.len()));
    }

    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(format!(
            "`{text}` is not laid out as `YYYY-MM-DDTHH:MM:SSZ`"
        ));
    }

    let number = |range: std::ops::Range<usize>| -> Result<u32, String> {
        let slice = &text[range];

        if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("`{slice}` in `{text}` is not a number: {SHAPE}"));
        }

        slice
            .parse()
            .map_err(|_| format!("`{slice}` in `{text}` is not a number: {SHAPE}"))
    };

    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;

    if !(1..=12).contains(&month) {
        return Err(format!(
            "`{text}` names month {month:02}: {SHAPE}, with the month between 01 and 12"
        ));
    }

    if day < 1 || day > days_in_month(year, month) {
        return Err(format!(
            "`{text}` names day {day:02} of a month that has {}",
            days_in_month(year, month)
        ));
    }

    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!(
            "`{text}` names {hour:02}:{minute:02}:{second:02}: {SHAPE}, with the hour at most 23, \
             the minute 59 and the second 59"
        ));
    }

    let days = days_from_civil(i64::from(year), month, day);

    if days < 0 {
        return Err(format!(
            "`{text}` is before `1970-01-01T00:00:00Z`, and absolute seconds start there"
        ));
    }

    Ok(days as u64 * SECONDS_PER_DAY
        + u64::from(hour) * SECONDS_PER_HOUR
        + u64::from(minute) * SECONDS_PER_MINUTE
        + u64::from(second))
}

/// Days since 1970-01-01 for a civil (proleptic Gregorian) date.
///
/// Howard Hinnant's `days_from_civil`: exact integer arithmetic, valid for any year, so no table, no
/// special case for leap years and no dependency is needed.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - 719_468
}

/// The civil date `days` after 1970-01-01: the inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };

    (year + i64::from(month <= 2), month as u32, day as u32)
}

/// The last day of `month` in `year`. `month` must already be within 1-12.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        _ => 28,
    }
}

/// The proleptic Gregorian rule, which is the rule every calendar the maker has ever seen follows.
fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// A whole draft: the document a maker writes, and the accessors that read it back in base units.
///
/// Every field differs from its [`QuoteTerms`](crate::terms::QuoteTerms) counterpart only in unit —
/// amounts are decimal XCH (or raw base units for a CAT), deadlines are [`Moment`]s, destinations are
/// [`Party`]s — so resolution is a mapping, not a decision. The four pieces that cannot be derived
/// offline stay exactly as a wallet export writes them: the maker's key, the backing coin triple, the
/// CAT lineage proof and the launcher coin.
///
/// This document does not refuse unknown fields, matching every other document in the crate
/// (`terms.rs:251`, `offer.rs:88`). A draft is one schema among several the CLI reads, and a stricter
/// one would reject a document the rest of the tool accepts; the required fields still catch a typo
/// that drops one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsDraft {
    /// Hex BLS public key controlling the maker's standard-layer coins.
    pub maker_public_key: Hex,
    /// Where the underlying lands on exercise and the strike at expiry. Omitted, it defaults to the
    /// maker's own standard-layer puzzle hash — the address change already goes to.
    #[serde(default)]
    pub creator: Option<Party>,
    /// The coin and asset the maker commits, with the amount in the asset's own unit.
    pub underlying: UnderlyingDraft,
    /// The strike asset and amount.
    pub strike: StrikeDraft,
    /// The option's expiry: a duration such as `30d`, a calendar instant, or absolute seconds.
    pub expiry: Moment,
    /// The deadline after which the offer cannot land. Signed into the offer, not committed into any
    /// hash, so it is stated as its own fact rather than folded into `expiry`.
    pub take_by: Moment,
    /// The premium the taker pays.
    pub premium: PremiumDraft,
    /// The XCH coin that funds the launcher. Required for, and only valid for, a CAT backing coin.
    #[serde(default)]
    pub launcher_coin: Option<CoinJson>,
    /// Optional `RESERVE_FEE` floor the taker must pay, as a decimal XCH amount.
    #[serde(default)]
    pub fee_floor: Option<XchAmount>,
}

impl TermsDraft {
    /// Parses the maker's public key, rejecting anything that is not 48 bytes of a usable G1 point.
    pub fn maker_public_key(&self) -> Result<PublicKey, SecError> {
        self.maker_public_key.public_key("maker_public_key")
    }

    /// The `RESERVE_FEE` floor in mojos: zero when the draft omits it, exactly as [`QuoteTerms`] does
    /// with its own `#[serde(default)]` field.
    ///
    /// [`QuoteTerms`]: crate::terms::QuoteTerms
    pub fn fee_floor(&self) -> Result<u64, SecError> {
        match &self.fee_floor {
            Some(amount) => amount.mojos("fee_floor"),
            None => Ok(0),
        }
    }
}

/// What the maker commits as the option's underlying, in draft units.
///
/// Mirrors [`BackingAsset`], reusing its [`CoinJson`] and [`BackingCatJson`] verbatim: a coin triple and
/// a lineage proof cannot be derived offline, so a draft carries them exactly as they were exported.
/// The amount sits inside the variant because only an XCH amount has a decimal form.
///
/// [`BackingAsset`]: crate::terms::BackingAsset
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnderlyingDraft {
    /// An XCH coin held at the maker's standard-layer puzzle hash.
    Xch {
        /// The XCH coin to spend.
        coin: CoinJson,
        /// How much XCH the option locks, as a decimal: `"1.5"`.
        amount: XchAmount,
    },

    /// A CAT coin, accompanied by a separate XCH launcher coin.
    Cat {
        /// The CAT coin to spend.
        coin: CoinJson,
        /// The CAT-specific terms.
        backing_cat: BackingCatJson,
        /// How much of the CAT the option locks, in base units: a CAT has no decimal scale to trust.
        amount: u64,
    },
}

impl UnderlyingDraft {
    /// The backing coin, exactly as the draft wrote it.
    pub fn coin(&self) -> &CoinJson {
        match self {
            Self::Xch { coin, .. } | Self::Cat { coin, .. } => coin,
        }
    }

    /// The locked amount in base units: a decimal XCH amount scaled exactly, a CAT amount as written.
    pub fn amount(&self) -> Result<u64, SecError> {
        match self {
            Self::Xch { amount, .. } => amount.mojos("underlying.amount"),
            Self::Cat { amount, .. } => Ok(*amount),
        }
    }

    /// The wire name of the backing kind, used in a rejection message.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Xch { .. } => "xch",
            Self::Cat { .. } => "cat",
        }
    }

    /// The resolved shape, with the coin and the CAT terms carried across unchanged.
    ///
    /// The amount stays outside it — [`QuoteTerms`](crate::terms::QuoteTerms) keeps `underlying_amount`
    /// beside `underlying` for the same reason: it has to be scaled before it is attached.
    pub fn backing_asset(&self) -> BackingAsset {
        match self {
            Self::Xch { coin, .. } => BackingAsset::Xch { coin: coin.clone() },
            Self::Cat {
                coin, backing_cat, ..
            } => BackingAsset::Cat {
                coin: coin.clone(),
                backing_cat: backing_cat.clone(),
            },
        }
    }
}

/// The strike asset and amount the option can be exercised for.
///
/// Mirrors [`StrikeType`] variant for variant, including the two kinds this tool does not support:
/// [`strike_type`](Self::strike_type) produces them and
/// [`QuoteTerms::strike_type`](crate::terms::QuoteTerms::strike_type) names and rejects them, so a maker
/// reads the rejection the rest of the tool already writes instead of a serde error about a variant the
/// draft never mentioned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StrikeDraft {
    /// An XCH strike, paid to the creator's puzzle hash.
    Xch {
        /// Strike amount as a decimal: `"2.0"`.
        amount: XchAmount,
    },
    /// A non-revocable CAT strike, paid to the creator's puzzle hash.
    Cat {
        /// Hex asset id.
        asset_id: Hex,
        /// Strike amount in the asset's base units.
        amount: u64,
    },
    /// Recognised so the draft can name it, then rejected when the terms are validated.
    RevocableCat {
        /// Hex asset id.
        asset_id: Hex,
        /// Hex hidden puzzle hash.
        hidden_puzzle_hash: Hex,
        /// Strike amount in the asset's base units.
        amount: u64,
    },
    /// Recognised so the draft can name it, then rejected when the terms are validated.
    Nft {
        /// Hex launcher id of the settlement NFT.
        launcher_id: Hex,
        /// Hex settlement puzzle hash.
        settlement_puzzle_hash: Hex,
        /// Strike amount.
        amount: u64,
    },
}

impl StrikeDraft {
    /// The strike amount in base units: a decimal XCH amount scaled exactly, a CAT amount as written.
    pub fn amount(&self) -> Result<u64, SecError> {
        match self {
            Self::Xch { amount } => amount.mojos("strike.amount"),
            Self::Cat { amount, .. }
            | Self::RevocableCat { amount, .. }
            | Self::Nft { amount, .. } => Ok(*amount),
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

    /// The resolved strike, with the amount scaled to base units.
    pub fn strike_type(&self) -> Result<StrikeType, SecError> {
        let amount = self.amount()?;

        Ok(match self {
            Self::Xch { .. } => StrikeType::Xch { amount },
            Self::Cat { asset_id, .. } => StrikeType::Cat {
                asset_id: asset_id.clone(),
                amount,
            },
            Self::RevocableCat {
                asset_id,
                hidden_puzzle_hash,
                ..
            } => StrikeType::RevocableCat {
                asset_id: asset_id.clone(),
                hidden_puzzle_hash: hidden_puzzle_hash.clone(),
                amount,
            },
            Self::Nft {
                launcher_id,
                settlement_puzzle_hash,
                ..
            } => StrikeType::Nft {
                launcher_id: launcher_id.clone(),
                settlement_puzzle_hash: settlement_puzzle_hash.clone(),
                amount,
            },
        })
    }
}

/// The premium the taker pays, in draft units.
///
/// Flat where [`QuoteTerms`](crate::terms::QuoteTerms) nests a `Premium` around a `PremiumAsset`: a maker
/// writes the recipient beside the amount, and a `kind` tag names the asset, which is how every other
/// document in the crate names one. [`asset`](Self::asset) reassembles the `PremiumAsset` the resolved
/// terms carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PremiumDraft {
    /// An XCH premium, settled against `SETTLEMENT_PAYMENT_HASH`.
    Xch {
        /// Premium amount as a decimal: `"0.05"`.
        amount: XchAmount,
        /// Where the premium goes: a bech32m address, or a `0x` puzzle hash.
        recipient: Party,
    },
    /// A CAT premium, settled against the CAT-curried settlement puzzle.
    Cat {
        /// Hex asset id.
        asset_id: Hex,
        /// Present for revocable CATs.
        #[serde(default)]
        hidden_puzzle_hash: Option<Hex>,
        /// Premium amount in the asset's base units.
        amount: u64,
        /// Where the premium goes.
        recipient: Party,
    },
}

impl PremiumDraft {
    /// The premium amount in base units: a decimal XCH amount scaled exactly, a CAT amount as written.
    pub fn amount(&self) -> Result<u64, SecError> {
        match self {
            Self::Xch { amount, .. } => amount.mojos("premium.amount"),
            Self::Cat { amount, .. } => Ok(*amount),
        }
    }

    /// Where the premium goes, still in whichever form the maker wrote it.
    pub fn recipient(&self) -> &Party {
        match self {
            Self::Xch { recipient, .. } | Self::Cat { recipient, .. } => recipient,
        }
    }

    /// The wire name of the premium asset kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Xch { .. } => "xch",
            Self::Cat { .. } => "cat",
        }
    }

    /// The resolved asset, with the CAT fields carried across unchanged.
    pub fn asset(&self) -> PremiumAsset {
        match self {
            Self::Xch { .. } => PremiumAsset::Xch,
            Self::Cat {
                asset_id,
                hidden_puzzle_hash,
                ..
            } => PremiumAsset::Cat {
                asset_id: asset_id.clone(),
                hidden_puzzle_hash: hidden_puzzle_hash.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bech32m address for `puzzle_hash` on `prefix`.
    fn address(puzzle_hash: Bytes32, prefix: &str) -> String {
        Address::new(puzzle_hash, prefix.to_string())
            .encode()
            .expect("the fixture address encodes")
    }

    fn hex32(bytes: [u8; 32]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    #[test]
    fn decimal_xch_scales_exactly() -> anyhow::Result<()> {
        for (text, mojos) in [
            ("0", 0),
            ("1", MOJOS_PER_XCH),
            ("0.1", MOJOS_PER_XCH / 10),
            ("0.5", MOJOS_PER_XCH / 2),
            ("12.5", 12 * MOJOS_PER_XCH + MOJOS_PER_XCH / 2),
            ("0.000000000001", 1),
            ("1.000000000001", MOJOS_PER_XCH + 1),
            ("  2  ", 2 * MOJOS_PER_XCH),
        ] {
            assert_eq!(
                XchAmount::new(text).mojos("amount")?,
                mojos,
                "`{text}` must scale to {mojos} mojos"
            );
        }

        Ok(())
    }

    #[test]
    fn a_thirteenth_fractional_digit_is_rejected() -> anyhow::Result<()> {
        let error = XchAmount::new("0.0000000000001")
            .mojos("premium.amount")
            .unwrap_err();

        assert!(
            error.to_string().contains("13 fractional digits"),
            "{error}"
        );

        Ok(())
    }

    #[test]
    fn malformed_decimals_name_the_field() -> anyhow::Result<()> {
        for text in [
            "", "   ", "1e12", "-1", "+1", "1.2.3", "1.", ".5", "1 000", "0x10", "1,5",
        ] {
            let error = XchAmount::new(text).mojos("underlying.amount").unwrap_err();

            assert!(
                error.to_string().contains("underlying.amount"),
                "`{text}` must report its field: {error}"
            );
        }

        Ok(())
    }

    #[test]
    fn amounts_beyond_the_u64_range_are_rejected() -> anyhow::Result<()> {
        let error = XchAmount::new("2000000000000")
            .mojos("strike.amount")
            .unwrap_err();

        assert!(error.to_string().contains("u64 mojo range"), "{error}");

        Ok(())
    }

    #[test]
    fn addresses_decode_to_their_puzzle_hash() -> anyhow::Result<()> {
        let puzzle_hash = Bytes32::new([3; 32]);

        for prefix in ["xch", "txch"] {
            assert_eq!(
                Party::new(address(puzzle_hash, prefix)).puzzle_hash(prefix, "creator")?,
                puzzle_hash
            );
        }

        Ok(())
    }

    #[test]
    fn hex_puzzle_hashes_are_accepted() -> anyhow::Result<()> {
        assert_eq!(
            Party::new(hex32([4; 32])).puzzle_hash("xch", "premium.recipient")?,
            Bytes32::new([4; 32])
        );

        Ok(())
    }

    #[test]
    fn an_address_from_another_network_is_named() -> anyhow::Result<()> {
        let error = Party::new(address(Bytes32::new([3; 32]), "txch"))
            .puzzle_hash("xch", "creator")
            .unwrap_err();

        // Reaching the prefix check is what this pins: `Address::decode` alone would have accepted the
        // txch address and silently produced a mainnet quote. The wording of the SDK's own error is
        // deliberately not asserted — only that the failure is ours, names the field, and is about a
        // prefix rather than a decode or length failure.
        assert!(matches!(&error, SecError::InvalidTerms(_)), "{error}");
        assert!(error.to_string().contains("creator"), "{error}");
        assert!(error.to_string().contains("prefix"), "{error}");

        Ok(())
    }

    #[test]
    fn a_party_that_is_neither_form_is_rejected() -> anyhow::Result<()> {
        // A 64-character hash *without* the `0x` marker: the two accepted forms have to stay
        // distinguishable, so this must not be read as hex.
        let marked = hex32([4; 32]);
        let bare = &marked[2..];

        for text in ["", "nope", "0x", bare] {
            let error = Party::new(text)
                .puzzle_hash("xch", "premium.recipient")
                .unwrap_err();

            assert!(
                error.to_string().contains("premium.recipient"),
                "`{text}` must report its field: {error}"
            );
        }

        Ok(())
    }

    #[test]
    fn both_scalars_are_transparent_over_their_string() -> anyhow::Result<()> {
        assert_eq!(serde_json::to_string(&XchAmount::new("0.5"))?, "\"0.5\"");
        assert_eq!(
            serde_json::to_string(&Party::new("xch1qqq"))?,
            "\"xch1qqq\""
        );
        assert_eq!(
            serde_json::from_str::<XchAmount>("\"0.5\"")?,
            XchAmount::new("0.5")
        );

        Ok(())
    }

    #[test]
    fn durations_are_measured_from_the_supplied_clock() -> anyhow::Result<()> {
        let now = 1_700_000_000;

        for (text, seconds) in [
            ("1s", 1),
            ("90m", 5_400),
            ("2h", 7_200),
            ("30d", 2_592_000),
            ("0d", 0),
            (" 30d ", 2_592_000),
        ] {
            assert_eq!(
                Moment::new(text).seconds(now, "expiry")?,
                now + seconds,
                "`{text}` must land {seconds} seconds after {now}"
            );
        }

        Ok(())
    }

    #[test]
    fn absolute_seconds_are_taken_as_written() -> anyhow::Result<()> {
        // The escape hatch, and today's form: a bare integer is not relative, so the clock is ignored.
        assert_eq!(
            Moment::new("1797292800").seconds(0, "take_by")?,
            1_797_292_800
        );
        assert_eq!(
            Moment::new("1797292800").seconds(1_700_000_000, "take_by")?,
            1_797_292_800
        );

        Ok(())
    }

    #[test]
    fn rfc3339_instants_convert_exactly() -> anyhow::Result<()> {
        for (text, seconds) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2000-03-01T00:00:00Z", 951_868_800),
            ("2024-02-29T12:34:56Z", 1_709_210_096),
            ("2026-12-15T00:00:00Z", 1_797_292_800),
            ("9999-12-31T23:59:59Z", 253_402_300_799),
        ] {
            assert_eq!(
                Moment::new(text).seconds(0, "expiry")?,
                seconds,
                "`{text}` must be {seconds} seconds after the epoch"
            );
        }

        Ok(())
    }

    #[test]
    fn rfc3339_round_trips_through_the_parser() -> anyhow::Result<()> {
        // The strongest check available without a calendar dependency: render, then read back. It pins
        // both directions of the civil-date arithmetic, including every leap-year shape (2000 is a leap
        // year, 1900 is not, 2024 is).
        for seconds in [
            0,
            951_868_800,
            1_709_210_096,
            1_797_292_800,
            253_402_300_799,
            1_700_000_000,
        ] {
            let rendered = rfc3339(seconds);

            assert_eq!(
                Moment::new(&rendered).seconds(0, "expiry")?,
                seconds,
                "`{rendered}` must read back as {seconds}"
            );
        }

        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");

        Ok(())
    }

    #[test]
    fn a_relative_deadline_without_a_clock_is_refused() -> anyhow::Result<()> {
        // The library must not invent a clock: a duration against `now == 0` would silently land the
        // deadline in 1970, which is exactly the kind of quiet wrongness a preview exists to prevent.
        let error = Moment::new("30d").seconds(0, "expiry").unwrap_err();

        assert!(error.to_string().contains("expiry"), "{error}");
        assert!(error.to_string().contains("--now"), "{error}");

        Ok(())
    }

    #[test]
    fn a_calendar_date_that_does_not_exist_is_rejected() -> anyhow::Result<()> {
        for text in [
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
        ] {
            let error = Moment::new(text)
                .seconds(1_700_000_000, "take_by")
                .unwrap_err();

            assert!(error.to_string().contains("take_by"), "{error}");
        }

        // The leap day the calendar does have is accepted, and one before the epoch is refused for the
        // reason it is refused: absolute seconds start at 1970.
        assert_eq!(
            Moment::new("2024-02-29T00:00:00Z").seconds(0, "take_by")?,
            1_709_164_800
        );

        let error = Moment::new("1969-12-31T23:59:59Z")
            .seconds(0, "take_by")
            .unwrap_err();

        assert!(error.to_string().contains("1970"), "{error}");

        Ok(())
    }

    #[test]
    fn malformed_moments_name_the_field_and_the_forms() -> anyhow::Result<()> {
        for text in [
            "",
            "   ",
            "later",
            "30x",
            "30 d",
            "-30d",
            "+30d",
            "1.5d",
            "d",
            "2026-12-15",
            "2026-12-15T00:00:00",
            "2026-12-15T00:00:00+01:00",
            "2026-12-15 00:00:00Z",
            "2026-12-15T00:00:00.500Z",
            "2026-12-15T00:00:00z",
            "1797292800.5",
            "30é",
        ] {
            let error = Moment::new(text)
                .seconds(1_700_000_000, "take_by")
                .unwrap_err();

            assert!(
                error.to_string().contains("take_by"),
                "`{text}` must report its field: {error}"
            );
        }

        // A rejection that is not a duration and not date-shaped still names all three accepted forms,
        // because that message is the only instruction the maker gets.
        let error = Moment::new("later")
            .seconds(1_700_000_000, "take_by")
            .unwrap_err();

        assert!(error.to_string().contains("30d"), "{error}");
        assert!(
            error.to_string().contains("2026-12-15T00:00:00Z"),
            "{error}"
        );
        assert!(error.to_string().contains("unix seconds"), "{error}");

        Ok(())
    }

    #[test]
    fn an_overflowing_duration_is_rejected() -> anyhow::Result<()> {
        for text in ["1000000000000000d", "18446744073709551616"] {
            let error = Moment::new(text)
                .seconds(1_700_000_000, "expiry")
                .unwrap_err();

            assert!(error.to_string().contains("u64 second range"), "{error}");
        }

        // The same duration from a clock low enough to hold it still resolves: the rejection is about
        // the range, not about the size of the number.
        assert_eq!(
            Moment::new("200000d").seconds(1_700_000_000, "expiry")?,
            1_700_000_000 + 17_280_000_000
        );

        Ok(())
    }

    #[test]
    fn a_moment_is_transparent_over_its_string() -> anyhow::Result<()> {
        assert_eq!(serde_json::to_string(&Moment::new("30d"))?, "\"30d\"");
        assert_eq!(
            serde_json::from_str::<Moment>("\"2026-12-15T00:00:00Z\"")?,
            Moment::new("2026-12-15T00:00:00Z")
        );

        Ok(())
    }

    /// The maker's public key, as a draft spells it.
    fn maker_key_hex() -> String {
        format!("0x{}", hex::encode(maker_key().to_bytes()))
    }

    fn maker_key() -> PublicKey {
        SecretKey::from_seed(&[7; 32]).public_key()
    }

    /// A complete draft, written the way a maker would: decimal amounts, a duration, a calendar instant
    /// and mainnet addresses. The shape is the design's Desired End State.
    fn draft_document() -> String {
        serde_json::json!({
            "maker_public_key": maker_key_hex(),
            "creator": address(Bytes32::new([7; 32]), "xch"),
            "underlying": {
                "kind": "xch",
                "coin": {
                    "parent_coin_info": hex32([1; 32]),
                    "puzzle_hash": hex32([2; 32]),
                    "amount": 2_000_000_000_000u64,
                },
                "amount": "1.5",
            },
            "strike": { "kind": "xch", "amount": "2.0" },
            "expiry": "30d",
            "take_by": "2026-12-15T00:00:00Z",
            "premium": {
                "kind": "xch",
                "amount": "0.05",
                "recipient": address(Bytes32::new([9; 32]), "xch"),
            },
            "fee_floor": "0.001",
        })
        .to_string()
    }

    /// A complete CAT draft: the same document with the raw base units a CAT has to carry, plus the
    /// launcher coin a CAT-underwritten quote needs.
    fn cat_draft_document() -> String {
        serde_json::json!({
            "maker_public_key": maker_key_hex(),
            "underlying": {
                "kind": "cat",
                "coin": {
                    "parent_coin_info": hex32([1; 32]),
                    "puzzle_hash": hex32([2; 32]),
                    "amount": 1_000u64,
                },
                "backing_cat": {
                    "asset_id": hex32([5; 32]),
                    "lineage_proof": {
                        "parent_parent_coin_info": hex32([3; 32]),
                        "parent_inner_puzzle_hash": hex32([4; 32]),
                        "parent_amount": 1_000u64,
                    },
                },
                "amount": 500u64,
            },
            "strike": { "kind": "cat", "asset_id": hex32([5; 32]), "amount": 2_500u64 },
            "expiry": "2026-12-15T00:00:00Z",
            "take_by": "2026-12-16T00:00:00Z",
            "premium": {
                "kind": "cat",
                "asset_id": hex32([5; 32]),
                "amount": 25u64,
                "recipient": address(Bytes32::new([9; 32]), "xch"),
            },
            "launcher_coin": {
                "parent_coin_info": hex32([6; 32]),
                "puzzle_hash": hex32([7; 32]),
                "amount": 1u64,
            },
        })
        .to_string()
    }

    #[test]
    fn a_complete_draft_reads_as_written() -> anyhow::Result<()> {
        let draft: TermsDraft = serde_json::from_str(&draft_document())?;

        assert_eq!(draft.maker_public_key()?, maker_key());
        assert_eq!(
            draft.creator,
            Some(Party::new(address(Bytes32::new([7; 32]), "xch")))
        );
        assert_eq!(draft.underlying.kind(), "xch");
        assert_eq!(draft.underlying.amount()?, 1_500_000_000_000);
        assert_eq!(draft.underlying.coin().amount, 2_000_000_000_000);
        assert_eq!(draft.strike.kind(), "xch");
        assert_eq!(draft.strike.amount()?, 2_000_000_000_000);
        assert_eq!(draft.expiry, Moment::new("30d"));
        assert_eq!(draft.take_by, Moment::new("2026-12-15T00:00:00Z"));
        assert_eq!(draft.premium.kind(), "xch");
        assert_eq!(draft.premium.amount()?, 50_000_000_000);
        assert_eq!(draft.fee_floor()?, 1_000_000_000);
        assert_eq!(draft.launcher_coin, None);

        // The relative deadline resolves, and the absolute one does not care when it is resolved.
        assert_eq!(
            draft.expiry.seconds(1_700_000_000, "expiry")?,
            1_700_000_000 + 2_592_000
        );
        assert_eq!(
            draft.take_by.seconds(1_700_000_000, "take_by")?,
            1_797_292_800
        );

        Ok(())
    }

    #[test]
    fn the_draft_round_trips_through_json() -> anyhow::Result<()> {
        // A draft is a document a maker hand-edits, so what the tool writes back has to be the same
        // document: `--output` never emits a draft today, but a preview-driven workflow starts from one.
        let draft: TermsDraft = serde_json::from_str(&draft_document())?;
        let written = serde_json::to_string_pretty(&draft)?;
        let reread: TermsDraft = serde_json::from_str(&written)?;

        assert_eq!(reread, draft);
        assert!(written.contains("\"1.5\""), "{written}");
        assert!(written.contains("\"30d\""), "{written}");

        Ok(())
    }

    #[test]
    fn cat_amounts_stay_raw_base_units() -> anyhow::Result<()> {
        // A CAT has no canonical decimal scale, so its amounts are never scaled — and are never parsed
        // as decimals either.
        let draft: TermsDraft = serde_json::from_str(&cat_draft_document())?;

        assert_eq!(draft.underlying.kind(), "cat");
        assert_eq!(draft.underlying.amount()?, 500);
        assert_eq!(draft.strike.amount()?, 2_500);
        assert_eq!(draft.premium.amount()?, 25);
        assert_eq!(draft.fee_floor()?, 0);
        assert!(draft.launcher_coin.is_some());

        let decimal = cat_draft_document().replace("\"amount\":500", "\"amount\":\"0.0000005\"");
        let error = serde_json::from_str::<TermsDraft>(&decimal).unwrap_err();

        assert!(error.to_string().contains("0.0000005"), "{error}");

        Ok(())
    }

    #[test]
    fn the_strike_carries_its_kind_through() -> anyhow::Result<()> {
        let draft: TermsDraft = serde_json::from_str(&draft_document())?;

        assert_eq!(
            draft.strike.strike_type()?,
            StrikeType::Xch {
                amount: 2_000_000_000_000
            }
        );

        // The two unsupported kinds survive resolution so `QuoteTerms::strike_type` — not the draft —
        // is what names and rejects them, keeping one rejection message for the whole tool.
        for (strike, expected) in [
            (
                serde_json::json!({
                    "kind": "cat",
                    "asset_id": hex32([5; 32]),
                    "amount": 2_500u64,
                }),
                StrikeType::Cat {
                    asset_id: Hex::new(hex32([5; 32])),
                    amount: 2_500,
                },
            ),
            (
                serde_json::json!({
                    "kind": "revocable_cat",
                    "asset_id": hex32([5; 32]),
                    "hidden_puzzle_hash": hex32([8; 32]),
                    "amount": 2_500u64,
                }),
                StrikeType::RevocableCat {
                    asset_id: Hex::new(hex32([5; 32])),
                    hidden_puzzle_hash: Hex::new(hex32([8; 32])),
                    amount: 2_500,
                },
            ),
            (
                serde_json::json!({
                    "kind": "nft",
                    "launcher_id": hex32([6; 32]),
                    "settlement_puzzle_hash": hex32([7; 32]),
                    "amount": 2_500u64,
                }),
                StrikeType::Nft {
                    launcher_id: Hex::new(hex32([6; 32])),
                    settlement_puzzle_hash: Hex::new(hex32([7; 32])),
                    amount: 2_500,
                },
            ),
        ] {
            let mut document: serde_json::Value = serde_json::from_str(&draft_document())?;
            document["strike"] = strike;
            let draft: TermsDraft = serde_json::from_value(document)?;

            assert_eq!(draft.strike.strike_type()?, expected);
            assert_eq!(draft.strike.kind(), expected.kind());
        }

        Ok(())
    }

    #[test]
    fn a_premium_keeps_its_recipient_and_asset() -> anyhow::Result<()> {
        let draft: TermsDraft = serde_json::from_str(&draft_document())?;
        let recipient = Party::new(address(Bytes32::new([9; 32]), "xch"));

        assert_eq!(draft.premium.asset(), PremiumAsset::Xch);
        assert_eq!(draft.premium.recipient(), &recipient);
        assert_eq!(
            draft
                .premium
                .recipient()
                .puzzle_hash("xch", "premium.recipient")?,
            Bytes32::new([9; 32])
        );

        // A CAT premium keeps the asset id and the absent hidden hash, so `QuoteTerms` can reject a
        // revocable CAT exactly as it does on the terms side.
        let cat: TermsDraft = serde_json::from_str(&cat_draft_document())?;

        assert_eq!(
            cat.premium.asset(),
            PremiumAsset::Cat {
                asset_id: Hex::new(hex32([5; 32])),
                hidden_puzzle_hash: None,
            }
        );

        Ok(())
    }

    #[test]
    fn fee_floor_defaults_to_zero() -> anyhow::Result<()> {
        let mut document: serde_json::Value = serde_json::from_str(&draft_document())?;
        document
            .as_object_mut()
            .expect("a draft is an object")
            .remove("fee_floor");

        let draft: TermsDraft = serde_json::from_value(document)?;

        assert_eq!(draft.fee_floor()?, 0);

        // A malformed floor is refused by the same accessor that reads a good one, naming its field.
        let mut document: serde_json::Value = serde_json::from_str(&draft_document())?;
        document["fee_floor"] = serde_json::json!("0.1.2");

        let draft: TermsDraft = serde_json::from_value(document)?;
        let error = draft.fee_floor().unwrap_err();

        assert!(error.to_string().contains("fee_floor"), "{error}");

        Ok(())
    }

    #[test]
    fn creator_is_optional() -> anyhow::Result<()> {
        // Omitted, the creator defaults to the maker's own puzzle hash — the one address the bundle is
        // guaranteed to use, because change goes there too.
        let mut document: serde_json::Value = serde_json::from_str(&draft_document())?;
        document
            .as_object_mut()
            .expect("a draft is an object")
            .remove("creator");

        let draft: TermsDraft = serde_json::from_value(document)?;

        assert_eq!(draft.creator, None);

        Ok(())
    }

    #[test]
    fn an_unknown_kind_is_rejected() -> anyhow::Result<()> {
        // The `kind` tag is the one dispatch point in the document, and an asset this tool cannot model
        // must fail at read time rather than resolve into something the preview misdescribes.
        for section in ["underlying", "strike", "premium"] {
            let mut document: serde_json::Value = serde_json::from_str(&draft_document())?;
            document[section]["kind"] = serde_json::json!("erc20");

            let error = serde_json::from_value::<TermsDraft>(document).unwrap_err();

            assert!(error.to_string().contains("erc20"), "`{section}`: {error}");
        }

        Ok(())
    }

    #[test]
    fn a_missing_deadline_is_rejected() -> anyhow::Result<()> {
        // Both deadlines are required by D6: the resolver adds no ordering check, so neither may be
        // allowed to slip through as absent.
        for field in ["expiry", "take_by"] {
            let mut document: serde_json::Value = serde_json::from_str(&draft_document())?;
            document
                .as_object_mut()
                .expect("a draft is an object")
                .remove(field);

            let error = serde_json::from_value::<TermsDraft>(document).unwrap_err();

            assert!(error.to_string().contains(field), "{error}");
        }

        Ok(())
    }

    #[test]
    fn a_draft_is_not_a_resolved_terms_document() -> anyhow::Result<()> {
        use crate::terms::QuoteTerms;

        // The migration contract: the two documents are told apart by content, so no verb can be handed
        // the wrong one without a word. A draft's decimal amounts are strings where terms carry `u64`,
        // so one cannot be read as the other even before the field names diverge.
        assert!(serde_json::from_str::<QuoteTerms>(&draft_document()).is_err());

        // The divergence is structural, not merely a type: a resolved document's second field is
        // `creator_puzzle_hash`, and a draft's is `creator`.
        let error = serde_json::from_value::<QuoteTerms>(serde_json::json!({
            "maker_public_key": maker_key_hex(),
        }))
        .unwrap_err();

        assert!(error.to_string().contains("creator_puzzle_hash"), "{error}");

        // And the other way round: a draft names `underlying` and `expiry`, where terms name
        // `underlying_amount` and `expiry_seconds`.
        let error = serde_json::from_value::<TermsDraft>(serde_json::json!({
            "maker_public_key": maker_key_hex(),
            "creator_puzzle_hash": hex32([9; 32]),
            "underlying_amount": 1_500_000_000_000u64,
            "expiry_seconds": 1_797_292_800u64,
            "take_by_seconds": 1_797_292_800u64,
        }))
        .unwrap_err();

        assert!(error.to_string().contains("underlying"), "{error}");

        Ok(())
    }
}

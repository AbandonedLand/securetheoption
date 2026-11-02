//! The local quote book: which backing coins are already committed, and to what.
//!
//! The book exists for one reason: a maker must not presign two different quotes over the same backing
//! coin. Both would be landable, only one can ever land, and the maker's coin would be committed twice
//! from the maker's own point of view. So the book is keyed by backing coin id and a second live quote
//! over a booked coin is a hard error.
//!
//! It is deliberately small: one JSON file, the whole map rewritten through a staging file on every
//! mutation. A single process owns it — cross-process locking is out of scope (see `## Scope`, "Not
//! Building"), so this module assumes one writer and does not retry, lock or recover.
//!
//! Retiring is local bookkeeping only. Nothing here can stop an already-published offer from landing,
//! so every message a caller derives from this module has to say so.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use chia_wallet_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::SecError;
use crate::offer::hex_bytes;
use crate::quote::Quote;
use crate::terms::{Hex, QuoteTerms};

/// The state of one booked quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    /// The terms are booked and the unsigned bundle was produced, but no offer file has been written.
    Quoted,
    /// An offer file exists, and stays landable until the quote's `take_by_seconds`.
    Sealed,
}

impl fmt::Display for QuoteStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Quoted => "quoted",
            Self::Sealed => "sealed",
        })
    }
}

/// The two files a sealed offer was written to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteArtifacts {
    /// The `.offer` or `.json` file a wallet imports.
    pub offer_path: String,
    /// The plaintext sidecar that travels with it.
    pub sidecar_path: String,
}

/// One booked quote.
///
/// `terms` and `launcher_id` are recorded as written, so `list` shows what was actually quoted instead
/// of re-deriving it, and `requote` can report the deadline the superseded offer keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteEntry {
    /// Whether an offer file exists yet.
    pub status: QuoteStatus,
    /// The option's identity on chain, as the quote computed it.
    pub launcher_id: Hex,
    /// The maker's terms, in full.
    pub terms: QuoteTerms,
    /// The offer file, once one has been written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_path: Option<String>,
    /// The sidecar file, once one has been written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_path: Option<String>,
}

/// What a re-quote replaced: the offer that is still out there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersededQuote {
    /// Whether the superseded entry had an offer file to its name.
    pub status: QuoteStatus,
    /// The superseded offer file, if there was one.
    pub offer_path: Option<String>,
    /// The superseded quote's take-by deadline, which the old offer keeps.
    pub take_by_seconds: u64,
}

/// The quote book: one JSON file holding `{ backing_coin_id -> entry }`.
#[derive(Debug, Clone)]
pub struct QuoteBook {
    path: PathBuf,
    quotes: BTreeMap<String, QuoteEntry>,
}

impl QuoteBook {
    /// Loads the book at `path`, treating a missing file as an empty book.
    ///
    /// Loading never writes. Every entry's key has to be the backing coin id its terms describe, so a
    /// hand-edited book cannot hide a second quote behind a key the guard would not check.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, SecError> {
        let path = path.into();

        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    quotes: BTreeMap::new(),
                });
            }
            Err(error) => return Err(SecError::io(&path, error)),
        };

        let quotes: BTreeMap<String, QuoteEntry> = serde_json::from_str(&text)?;

        for (key, entry) in &quotes {
            let coin_id = book_key(entry.terms.backing_coin()?.coin_id());

            if *key != coin_id {
                return Err(SecError::terms(format!(
                    "the quote book keys `{key}` but that entry's terms describe the backing coin \
                     {coin_id}: the key has to be the backing coin id"
                )));
            }
        }

        Ok(Self { path, quotes })
    }

    /// The file this book is read from and written to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The booked quotes, ordered by backing coin id.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &QuoteEntry)> {
        self.quotes
            .iter()
            .map(|(key, entry)| (key.as_str(), entry))
    }

    /// How many quotes are booked.
    pub fn len(&self) -> usize {
        self.quotes.len()
    }

    /// Whether the book is empty.
    pub fn is_empty(&self) -> bool {
        self.quotes.is_empty()
    }

    /// The booked quote for a backing coin, if there is one.
    pub fn get(&self, backing_coin_id: Bytes32) -> Option<&QuoteEntry> {
        self.quotes.get(&book_key(backing_coin_id))
    }

    /// Books a freshly created quote, refusing a second live quote over the same coin.
    pub fn create(&mut self, quote: &Quote) -> Result<(), SecError> {
        let key = book_key(quote.terms.backing_coin()?.coin_id());

        self.refuse_live_quote(&key)?;

        let mut quotes = self.quotes.clone();
        quotes.insert(key, entry(quote, QuoteStatus::Quoted, None));

        self.commit(quotes)
    }

    /// Records the files a quote's offer was written to.
    ///
    /// A quote that was only booked is promoted; a coin that was never booked is recorded, so an offer
    /// sealed outside the expected `create` -> `seal` order is still tracked. A *second* sealed offer
    /// for one coin is refused: that is exactly the double commit the book exists to prevent.
    pub fn mark_sealed(
        &mut self,
        quote: &Quote,
        artifacts: QuoteArtifacts,
    ) -> Result<(), SecError> {
        let key = book_key(quote.terms.backing_coin()?.coin_id());

        if let Some(existing) = self.quotes.get(&key)
            && existing.status == QuoteStatus::Sealed
        {
            return Err(SecError::CoinAlreadyQuoted {
                coin_id: key,
                offer: existing.offer_path.clone().unwrap_or_default(),
            });
        }

        let mut quotes = self.quotes.clone();
        quotes.insert(key, entry(quote, QuoteStatus::Sealed, Some(artifacts)));

        self.commit(quotes)
    }

    /// Replaces a booked quote with a new one over the same backing coin.
    ///
    /// Re-quoting is a re-sign, not an invalidation: the returned [`SupersededQuote`] is what a caller
    /// needs to say that the old offer is still landable until its own deadline.
    pub fn requote(&mut self, quote: &Quote) -> Result<SupersededQuote, SecError> {
        let key = book_key(quote.terms.backing_coin()?.coin_id());

        let previous = self
            .quotes
            .get(&key)
            .ok_or_else(|| SecError::UnknownQuotedCoin(key.clone()))?;

        let superseded = SupersededQuote {
            status: previous.status,
            offer_path: previous.offer_path.clone(),
            take_by_seconds: previous.terms.take_by_seconds,
        };

        let mut quotes = self.quotes.clone();
        quotes.insert(key, entry(quote, QuoteStatus::Quoted, None));

        self.commit(quotes)?;

        Ok(superseded)
    }

    /// Removes a booked quote and returns it, so a caller can report the deadline the offer keeps.
    pub fn retire(&mut self, backing_coin_id: Bytes32) -> Result<QuoteEntry, SecError> {
        let key = book_key(backing_coin_id);

        let retired = self
            .quotes
            .get(&key)
            .ok_or_else(|| SecError::UnknownQuotedCoin(key.clone()))?
            .clone();

        let mut quotes = self.quotes.clone();
        quotes.remove(&key);

        self.commit(quotes)?;

        Ok(retired)
    }

    /// Refuses a coin that already has a live quote.
    fn refuse_live_quote(&self, key: &str) -> Result<(), SecError> {
        let Some(existing) = self.quotes.get(key) else {
            return Ok(());
        };

        Err(SecError::CoinAlreadyQuoted {
            coin_id: key.to_string(),
            offer: existing
                .offer_path
                .clone()
                .unwrap_or_else(|| "nothing sealed yet".to_string()),
        })
    }

    /// Writes the whole map through a staging file, then adopts it as the new in-memory state.
    ///
    /// Adopting only after the write succeeds is what keeps the in-memory book describing the file: a
    /// failed write leaves the caller holding the map that is still on disk.
    fn commit(&mut self, quotes: BTreeMap<String, QuoteEntry>) -> Result<(), SecError> {
        let next = Self {
            path: self.path.clone(),
            quotes,
        };

        next.write()?;
        self.quotes = next.quotes;

        Ok(())
    }

    /// Serialises the map to `<path>.tmp`, flushes it, and renames it into place.
    fn write(&self) -> Result<(), SecError> {
        let text = serde_json::to_string_pretty(&self.quotes)?;
        let temp = temp_path(&self.path);

        let mut file = std::fs::File::create(&temp).map_err(|error| SecError::io(&temp, error))?;

        file.write_all(format!("{text}\n").as_bytes())
            .map_err(|error| SecError::io(&temp, error))?;

        // The rename is what a reader sees atomically; the flush is what puts the bytes on disk before
        // that happens, so a crash cannot leave the renamed file short.
        file.sync_all()
            .map_err(|error| SecError::io(&temp, error))?;

        std::fs::rename(&temp, &self.path).map_err(|error| SecError::io(&self.path, error))
    }
}

/// The book's key for a backing coin: the id in the `0x`-prefixed hex the rest of the tool uses.
fn book_key(backing_coin_id: Bytes32) -> String {
    hex_bytes(backing_coin_id.to_bytes())
}

/// The staging file every write goes through, so a reader sees either the whole old book or the whole
/// new one.
fn temp_path(path: &Path) -> PathBuf {
    let mut staging = path.as_os_str().to_owned();
    staging.push(".tmp");

    PathBuf::from(staging)
}

/// Renders one booked quote.
fn entry(quote: &Quote, status: QuoteStatus, artifacts: Option<QuoteArtifacts>) -> QuoteEntry {
    let (offer_path, sidecar_path) = match artifacts {
        None => (None, None),
        Some(artifacts) => (Some(artifacts.offer_path), Some(artifacts.sidecar_path)),
    };

    QuoteEntry {
        status,
        launcher_id: Hex(hex_bytes(quote.launcher_id.to_bytes())),
        terms: quote.terms.clone(),
        offer_path,
        sidecar_path,
    }
}

#[cfg(test)]
mod tests {
    use crate::terms::{BackingAsset, CoinJson, Premium, PremiumAsset, StrikeType};

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

    fn xch_terms(parent: [u8; 32], backing_amount: u64) -> QuoteTerms {
        let (maker_public_key, maker_puzzle_hash) = maker();

        QuoteTerms {
            maker_public_key,
            creator_puzzle_hash: hex32([9; 32]),
            underlying: BackingAsset::Xch {
                coin: CoinJson {
                    parent_coin_info: hex32(parent),
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

    fn artifacts() -> QuoteArtifacts {
        QuoteArtifacts {
            offer_path: "acme.offer".to_string(),
            sidecar_path: "acme-sidecar.json".to_string(),
        }
    }

    /// A book path under the OS temp directory, unique per test name and process.
    fn book_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("securetheoption-{}-{name}", std::process::id()));

        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        dir.join("quotes.json")
    }

    #[test]
    fn a_missing_book_starts_empty() -> anyhow::Result<()> {
        let path = book_path("missing");
        let book = QuoteBook::load(&path)?;

        assert!(book.is_empty());
        assert_eq!(book.len(), 0);
        assert_eq!(book.entries().count(), 0);
        assert!(!path.exists(), "loading must not create the book");

        Ok(())
    }

    #[test]
    fn create_records_the_quote() -> anyhow::Result<()> {
        let path = book_path("create");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;
        let coin_id = quote.terms.backing_coin()?.coin_id();

        let mut book = QuoteBook::load(&path)?;
        book.create(&quote)?;

        let entry = book.get(coin_id).expect("the quote is booked");
        assert_eq!(entry.status, QuoteStatus::Quoted);
        assert_eq!(
            entry.launcher_id,
            Hex(hex_bytes(quote.launcher_id.to_bytes()))
        );
        assert_eq!(entry.terms, quote.terms);
        assert_eq!(entry.offer_path, None);
        assert_eq!(entry.sidecar_path, None);

        // The write reaches disk, not just the in-memory map.
        let reloaded = QuoteBook::load(&path)?;
        assert_eq!(reloaded.get(coin_id), book.get(coin_id));

        Ok(())
    }

    #[test]
    fn a_second_live_quote_is_refused_and_leaves_the_file_untouched() -> anyhow::Result<()> {
        let path = book_path("double-commit");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;

        let mut book = QuoteBook::load(&path)?;
        book.create(&quote)?;

        let before = std::fs::read(&path)?;
        let error = book.create(&quote).unwrap_err();

        assert!(
            matches!(error, SecError::CoinAlreadyQuoted { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("nothing sealed yet"), "{error}");
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "a refused quote must not touch the book"
        );
        assert!(
            !temp_path(&path).exists(),
            "a refused quote must not leave a staging file"
        );

        Ok(())
    }

    #[test]
    fn sealing_records_the_artifacts() -> anyhow::Result<()> {
        let path = book_path("sealed");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;
        let coin_id = quote.terms.backing_coin()?.coin_id();

        let mut book = QuoteBook::load(&path)?;
        book.create(&quote)?;
        book.mark_sealed(&quote, artifacts())?;

        let entry = book.get(coin_id).expect("the quote is booked");
        assert_eq!(entry.status, QuoteStatus::Sealed);
        assert_eq!(entry.offer_path.as_deref(), Some("acme.offer"));
        assert_eq!(entry.sidecar_path.as_deref(), Some("acme-sidecar.json"));

        let reloaded = QuoteBook::load(&path)?;
        assert_eq!(reloaded.get(coin_id), book.get(coin_id));

        Ok(())
    }

    #[test]
    fn a_second_sealed_offer_for_one_coin_is_refused() -> anyhow::Result<()> {
        let path = book_path("sealed-twice");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;

        let mut book = QuoteBook::load(&path)?;
        book.mark_sealed(&quote, artifacts())?;

        let before = std::fs::read(&path)?;
        let error = book.mark_sealed(&quote, artifacts()).unwrap_err();

        assert!(
            matches!(error, SecError::CoinAlreadyQuoted { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("acme.offer"), "{error}");
        assert_eq!(std::fs::read(&path)?, before);
        assert!(!temp_path(&path).exists());

        Ok(())
    }

    #[test]
    fn sealing_a_coin_outside_the_book_records_it() -> anyhow::Result<()> {
        let path = book_path("seal-out-of-band");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;
        let coin_id = quote.terms.backing_coin()?.coin_id();

        let mut book = QuoteBook::load(&path)?;
        book.mark_sealed(&quote, artifacts())?;

        assert_eq!(
            book.get(coin_id).map(|entry| entry.status),
            Some(QuoteStatus::Sealed)
        );

        Ok(())
    }

    #[test]
    fn requote_reports_the_offer_that_stays_landable() -> anyhow::Result<()> {
        let path = book_path("requote");
        let first = Quote::new(xch_terms([1; 32], 1_000))?;

        let mut book = QuoteBook::load(&path)?;
        book.create(&first)?;
        book.mark_sealed(&first, artifacts())?;

        let mut terms = xch_terms([1; 32], 1_000);
        terms.take_by_seconds = 1_720_000_000;
        terms.strike = StrikeType::Xch { amount: 2_700 };
        let second = Quote::new(terms)?;

        let superseded = book.requote(&second)?;

        assert_eq!(superseded.status, QuoteStatus::Sealed);
        assert_eq!(superseded.offer_path.as_deref(), Some("acme.offer"));
        assert_eq!(superseded.take_by_seconds, 1_710_000_000);

        let entry = book
            .get(second.terms.backing_coin()?.coin_id())
            .expect("the re-quote is booked");
        assert_eq!(entry.status, QuoteStatus::Quoted);
        assert_eq!(entry.terms, second.terms);
        assert_eq!(entry.offer_path, None);
        assert_eq!(book.len(), 1, "one live quote per coin");

        Ok(())
    }

    #[test]
    fn requote_of_an_unknown_coin_is_refused() -> anyhow::Result<()> {
        let path = book_path("requote-unknown");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;

        let mut book = QuoteBook::load(&path)?;
        let error = book.requote(&quote).unwrap_err();

        assert!(
            matches!(error, SecError::UnknownQuotedCoin(_)),
            "{error}"
        );
        assert!(!path.exists(), "a refused re-quote must not create the book");

        Ok(())
    }

    #[test]
    fn retire_removes_the_entry_and_keeps_the_deadline() -> anyhow::Result<()> {
        let path = book_path("retire");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;
        let coin_id = quote.terms.backing_coin()?.coin_id();

        let mut book = QuoteBook::load(&path)?;
        book.create(&quote)?;
        book.mark_sealed(&quote, artifacts())?;

        let retired = book.retire(coin_id)?;

        assert_eq!(retired.status, QuoteStatus::Sealed);
        assert_eq!(retired.offer_path.as_deref(), Some("acme.offer"));
        assert_eq!(retired.terms.take_by_seconds, 1_710_000_000);
        assert!(book.is_empty());
        assert!(QuoteBook::load(&path)?.is_empty(), "the removal is on disk");

        Ok(())
    }

    #[test]
    fn retire_of_an_unknown_coin_is_refused() -> anyhow::Result<()> {
        let path = book_path("retire-unknown");
        let book = QuoteBook::load(&path)?;

        let mut book = book;
        let error = book.retire(Bytes32::new([42; 32])).unwrap_err();

        assert!(
            matches!(error, SecError::UnknownQuotedCoin(_)),
            "{error}"
        );

        Ok(())
    }

    #[test]
    fn the_book_refuses_a_key_that_is_not_the_backing_coin_id() -> anyhow::Result<()> {
        let path = book_path("bad-key");
        let quote = Quote::new(xch_terms([1; 32], 1_000))?;

        let mut book = QuoteBook::load(&path)?;
        book.create(&quote)?;

        let entry = book
            .get(quote.terms.backing_coin()?.coin_id())
            .expect("the quote is booked")
            .clone();

        let mut document: BTreeMap<String, QuoteEntry> = BTreeMap::new();
        document.insert(hex_bytes([9; 32]), entry);
        std::fs::write(&path, serde_json::to_string_pretty(&document)?)?;

        let error = QuoteBook::load(&path).unwrap_err();
        assert!(error.to_string().contains("backing coin"), "{error}");

        Ok(())
    }

    #[test]
    fn the_book_is_written_in_a_stable_order() -> anyhow::Result<()> {
        let first = Quote::new(xch_terms([1; 32], 1_000))?;
        let second = Quote::new(xch_terms([2; 32], 1_000))?;

        let left_path = book_path("order-left");
        let right_path = book_path("order-right");

        let mut left = QuoteBook::load(&left_path)?;
        left.create(&first)?;
        left.create(&second)?;

        let mut right = QuoteBook::load(&right_path)?;
        right.create(&second)?;
        right.create(&first)?;

        // The map is ordered by key, so the same quotes produce the same bytes whatever order they
        // were booked in — which is what keeps the file diffable.
        assert_eq!(
            std::fs::read_to_string(&left_path)?,
            std::fs::read_to_string(&right_path)?
        );

        Ok(())
    }
}

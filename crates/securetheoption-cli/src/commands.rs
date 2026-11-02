//! The seven subcommands.
//!
//! Every one of them is offline: they read and write files, hash, and print. Nothing here signs, and
//! nothing here opens a socket (Verification Note 10) — the maker's signature comes from an external
//! signer (FR8), and whether to take an offer is the taker's decision.

use std::path::Path;

use anyhow::{Context, Result};
use chia_wallet_sdk::prelude::*;
use securetheoption::draft::MOJOS_PER_XCH;
use securetheoption::{
    Hex, OfferFormat, PremiumAsset, Quote, QuoteArtifacts, QuoteBook, QuoteStatus, QuoteTerms,
    ResolveContext, SecError, SidecarSource, SupersededQuote, TermsDraft, VerifyReport,
    artifact_file_names, build_maker_bundle, resolve, rfc3339, seal as seal_offer,
    verify as verify_offer,
};

use crate::args::{
    CreateCommand, ListCommand, Network, PrepareCommand, RequoteCommand, RetireCommand,
    SealCommand, VerifyCommand,
};
use crate::json::{derived_ids, hex_bytes, spend_bundle_from_text, strike_json, unsigned_document};

/// Resolves the maker's draft, dry-runs the bundle, and previews what the terms commit to.
///
/// Read-only apart from `--output`. Nothing is signed, nothing is sealed, and the quote book is loaded
/// only to warn about an already-committed backing coin and never written (D8): booking the coin here
/// would be exactly the commitment the maker is still deciding about.
pub fn prepare(args: &PrepareCommand) -> Result<()> {
    let draft = load_draft(&args.draft)?;

    let terms = resolve(
        &draft,
        &ResolveContext {
            now_seconds: match args.now {
                Some(now) => now,
                None => unix_now()?,
            },
            address_prefix: args.network.address_prefix(),
        },
    )
    .context("the draft cannot be resolved into terms")?;

    let quote = Quote::new(terms).context("the draft's terms cannot produce a quote")?;

    // The dry run: exactly the hashing `create` does, so a preview never promises a bundle that does
    // not build. The bundle is dropped — nothing here signs it, writes it, or claims it is landable.
    build_maker_bundle(&quote).context("failed to build the maker spend bundle")?;

    let warnings: Vec<String> = book_warning(&QuoteBook::load(&args.book)?, &quote)?
        .into_iter()
        .collect();

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&preview_document(&quote, &warnings)?)?
        );
    } else {
        // stderr, so stdout stays a document a shell can redirect (FR10).
        for warning in &warnings {
            eprintln!("warning: {warning}");
        }

        println!("{}", preview_text(&quote, args.network)?);
        println!("dry run: the maker bundle builds; nothing signed, nothing booked");
    }

    if let Some(path) = &args.output {
        // The resolved terms, in the shape `create --terms` reads. `prepare` writes a document, never a
        // bundle: the maker still signs out of process, and the file is the same one every later verb
        // takes.
        let document = serde_json::to_string_pretty(&quote.terms)
            .context("failed to serialize the resolved terms")?;

        write_text(path, &document)?;

        // A note about a side effect, on stderr so `--json` leaves stdout exactly one parseable
        // document — the same reason `requote` sends its superseded note there (FR10, FR14).
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

/// Precomputes the quote, books the backing coin, and emits the unsigned bundle for a signer.
pub fn create(args: &CreateCommand) -> Result<()> {
    let quote = Quote::new(load_terms(&args.terms)?).context("the terms cannot produce a quote")?;
    let bundle = build_maker_bundle(&quote).context("failed to build the maker spend bundle")?;

    // Booked before anything is emitted: a refused double commit must not leave an unsigned bundle
    // behind, because the maker's next step is to sign it.
    let mut book = QuoteBook::load(&args.book)?;
    book.create(&quote)?;

    emit_unsigned(&quote, &bundle, args.network, args.output.as_deref())
}

/// Binds the maker's out-of-process signature into an offer and writes both artifacts.
pub fn seal(args: &SealCommand) -> Result<()> {
    let quote = Quote::new(load_terms(&args.terms)?).context("the terms cannot produce a quote")?;
    let signed = spend_bundle_from_text(&read_text(&args.signed, "signed spend bundle")?)?;

    let format = OfferFormat::from(args.format);
    let sealed = seal_offer(&quote, &signed, format).context("refusing to seal that bundle")?;

    let (offer_path, sidecar_path) = artifact_file_names(&args.output, format);
    let backing_coin_id = quote.terms.backing_coin()?.coin_id();

    // The double-commit guard runs before the filesystem: a second landable offer over one coin is
    // exactly what the book exists to refuse, and it must not reach disk to be refused afterwards.
    let mut book = QuoteBook::load(&args.book)?;

    if let Some(existing) = book.get(backing_coin_id)
        && existing.status == QuoteStatus::Sealed
    {
        return Err(SecError::CoinAlreadyQuoted {
            coin_id: hex_bytes(backing_coin_id.to_bytes()),
            offer: existing.offer_path.clone().unwrap_or_default(),
        }
        .into());
    }

    write_text(Path::new(&offer_path), sealed.offer_text())?;
    write_text(Path::new(&sidecar_path), sealed.sidecar_text())?;

    // Recorded only once both files exist, so the book never names an artifact that is not there.
    book.mark_sealed(
        &quote,
        QuoteArtifacts {
            offer_path: offer_path.clone(),
            sidecar_path: sidecar_path.clone(),
        },
    )?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "offer_path": &offer_path,
                "sidecar_path": &sidecar_path,
                "format": sealed.sidecar.format,
                "launcher_id": hex_bytes(quote.launcher_id.to_bytes()),
                "take_by_seconds": quote.terms.take_by_seconds,
            }))?
        );
    } else {
        println!(
            "wrote {offer_path} and {sidecar_path} (launcher {}, take-by {})",
            hex_bytes(quote.launcher_id.to_bytes()),
            quote.terms.take_by_seconds,
        );
    }

    Ok(())
}

/// Checks a published offer against its sidecar and reports what it could not model.
///
/// A mismatch exits non-zero (FR7): a taker scripting an offer has to be able to trust the exit status,
/// and a bundle that half-matches is worse than one that plainly fails.
pub fn verify(args: &VerifyCommand) -> Result<()> {
    let offer = spend_bundle_from_text(&read_text(&args.offer, "offer")?)?;

    let sidecar: SidecarSource = serde_json::from_str(&read_text(&args.sidecar, "sidecar")?)
        .with_context(|| format!("failed to parse the sidecar at {}", args.sidecar.display()))?;

    match verify_offer(&offer, sidecar) {
        Ok(report) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report_json(&report)?)?);
            } else {
                print_report(&report, args.network)?;
            }

            Ok(())
        }
        Err(SecError::Verification(errors)) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": false,
                        "errors": &errors,
                    }))?
                );
            } else {
                for error in &errors {
                    eprintln!("{error}");
                }
            }

            // The exit status is the machine-readable half of the verdict (FR7).
            std::process::exit(1);
        }
        Err(error) => Err(error.into()),
    }
}

/// Shows every booked quote, and whether an offer file is still out there.
pub fn list(args: &ListCommand) -> Result<()> {
    let book = QuoteBook::load(&args.book)?;

    if args.json {
        let quotes = book
            .entries()
            .map(|(backing_coin_id, entry)| {
                serde_json::json!({
                    "backing_coin_id": backing_coin_id,
                    "status": entry.status,
                    "launcher_id": &entry.launcher_id,
                    "expiry_seconds": entry.terms.expiry_seconds,
                    "take_by_seconds": entry.terms.take_by_seconds,
                    "offer_path": &entry.offer_path,
                    "sidecar_path": &entry.sidecar_path,
                })
            })
            .collect::<Vec<_>>();

        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "book": book.path().display().to_string(),
                "quotes": quotes,
            }))?
        );

        return Ok(());
    }

    if book.is_empty() {
        println!("no quotes in {}", book.path().display());

        return Ok(());
    }

    for (backing_coin_id, entry) in book.entries() {
        println!(
            "{backing_coin_id}  {:<7}  take-by {:<12} expiry {:<12} {}",
            entry.status,
            entry.terms.take_by_seconds,
            entry.terms.expiry_seconds,
            entry.offer_path.as_deref().unwrap_or("-"),
        );
    }

    Ok(())
}

/// Replaces a booked quote with new terms and emits the new unsigned bundle.
///
/// Re-quoting is a re-sign, not an invalidation: the superseded offer file is still landable until its
/// own deadline, so the note goes to stderr and stdout stays a document a shell can redirect (FR10).
pub fn requote(args: &RequoteCommand) -> Result<()> {
    let quote = Quote::new(load_terms(&args.terms)?).context("the terms cannot produce a quote")?;
    let bundle = build_maker_bundle(&quote).context("failed to build the maker spend bundle")?;

    let mut book = QuoteBook::load(&args.book)?;
    let superseded = book.requote(&quote)?;

    eprintln!(
        "re-quoted {}; {}",
        hex_bytes(quote.terms.backing_coin()?.coin_id().to_bytes()),
        superseded_message(&superseded),
    );

    emit_unsigned(&quote, &bundle, args.network, args.output.as_deref())
}

/// Stops advertising a quote locally.
///
/// Retiring is bookkeeping only: nothing here can stop an already published offer from landing, so the
/// message says what the deadline is rather than claiming the quote is dead (FR11).
pub fn retire(args: &RetireCommand) -> Result<()> {
    let backing_coin_id = Hex::new(args.backing_coin_id.clone()).bytes32("backing_coin_id")?;

    let mut book = QuoteBook::load(&args.book)?;
    let retired = book.retire(backing_coin_id)?;

    if args.json {
        // `landable_offer` names the file that may still land, instead of a blanket `landable: true`:
        // a quote that was never sealed has nothing out there, and saying otherwise would be the one
        // claim FR11 forbids this command from making.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "backing_coin_id": hex_bytes(backing_coin_id.to_bytes()),
                "status": retired.status,
                "landable_offer": &retired.offer_path,
                "take_by_seconds": retired.terms.take_by_seconds,
            }))?
        );

        return Ok(());
    }

    match &retired.offer_path {
        Some(path) => println!(
            "retired locally; {path} remains landable until {} (no on-chain invalidation)",
            retired.terms.take_by_seconds
        ),
        None => println!("retired locally; no offer file had been written for it yet"),
    }

    Ok(())
}

/// Serialises the unsigned bundle document and puts it on stdout (and on disk, if asked).
fn emit_unsigned(
    quote: &Quote,
    bundle: &SpendBundle,
    network: Network,
    output: Option<&Path>,
) -> Result<()> {
    let document = serde_json::to_string_pretty(&unsigned_document(quote, bundle, network)?)
        .context("failed to serialize the unsigned spend bundle")?;

    if let Some(path) = output {
        write_text(path, &document)?;
    }

    println!("{document}");

    Ok(())
}

/// Prints the summary FR7 asks for: what the option locks, for what strike, until when, and what the
/// taker pays for it.
fn print_report(report: &VerifyReport, network: Network) -> Result<()> {
    let terms = &report.quote.terms;

    let recipient = Address::new(
        terms.premium_recipient()?,
        network.address_prefix().to_string(),
    )
    .encode()
    .context("failed to render the premium recipient as an address")?;

    println!("Quote valid.");
    println!(
        "  launcher         {}",
        hex_bytes(report.quote.launcher_id.to_bytes())
    );
    println!(
        "  option coin      {}",
        hex_bytes(report.quote.option_coin.coin_id().to_bytes())
    );
    println!("  underlying       {}", underlying_label(&report.quote)?);
    println!(
        "  strike           {}",
        strike_label(&report.metadata.strike_type)
    );
    println!(
        "  expiry           {}     take-by {}",
        terms.expiry_seconds, terms.take_by_seconds
    );
    println!("  premium          {} -> {recipient}", premium_label(terms));
    println!("  premium payment  {}", report.premium_payment_hash.0);
    println!(
        "  unmodeled conditions: {}",
        report.unmodeled_conditions.len()
    );

    for condition in &report.unmodeled_conditions {
        println!(
            "    {} {}",
            hex_bytes(condition.coin_id.to_bytes()),
            condition.condition
        );
    }

    Ok(())
}

/// The JSON form of a verified offer, so a script needs no scraping.
fn report_json(report: &VerifyReport) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "valid": true,
        "launcher_id": hex_bytes(report.quote.launcher_id.to_bytes()),
        "option_coin_id": hex_bytes(report.quote.option_coin.coin_id().to_bytes()),
        "terms": serde_json::to_value(&report.quote.terms)?,
        "derived": derived_ids(&report.quote)?,
        "metadata": {
            "expiration_seconds": report.metadata.expiration_seconds,
            "strike": strike_json(&report.metadata.strike_type),
        },
        "modeled": {
            "take_by": report.modeled.take_by,
            "premium_assertion": hex_bytes(report.modeled.premium_assertion.to_bytes()),
        },
        "premium_payment_hash": report.premium_payment_hash.0,
        "unmodeled_conditions": report
            .unmodeled_conditions
            .iter()
            .map(|condition| serde_json::json!({
                "coin_id": hex_bytes(condition.coin_id.to_bytes()),
                "condition": condition.condition,
            }))
            .collect::<Vec<_>>(),
    }))
}

/// The preview as a document, so a script needs no scraping and a test can assert it.
///
/// The ids come from [`derived_ids`] — the sidecar's own summary — rather than being listed again, so
/// the preview cannot drift from what a taker verifies against. `commitment` is the distinction
/// Verification Note 8 requires, stated in the research's own three tiers: what the option's hashes
/// commit to, what only the maker's signature commits to, and what neither binds.
pub fn preview_json(quote: &Quote) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "terms": serde_json::to_value(&quote.terms)?,
        "derived": derived_ids(quote)?,
        "commitment": {
            "hash_committed": [
                "launcher_id",
                "creator_puzzle_hash",
                "underlying_amount",
                "strike",
                "expiry_seconds",
            ],
            "signature_committed": ["take_by_seconds", "premium"],
            "informational": ["fee_floor", "underlying.coin", "launcher_coin"],
        },
    }))
}

/// The document `prepare --json` emits: the preview, the dry-run verdict, and any book warning.
///
/// Assembled here rather than in the verb so the whole stdout payload is one value a test can assert —
/// and so `prepare` writes exactly one thing to stdout whatever `--json` says. Every note about a side
/// effect goes to stderr, which is what keeps stdout redirectable (FR10, FR14).
pub fn preview_document(quote: &Quote, warnings: &[String]) -> Result<serde_json::Value> {
    let mut document = preview_json(quote)?;

    document["dry_run"] = serde_json::json!({
        "maker_bundle_builds": true,
        "signed": false,
        "booked": false,
    });
    document["warnings"] = serde_json::json!(warnings);

    Ok(document)
}

/// The preview as the lines the maker reads before signing anything.
///
/// Every amount carries both forms — the decimal a maker writes and the base units the CLVM commits to
/// (Verification Note 5) — including the `fee floor` when the draft sets one. `take_by` is labelled for
/// what it is: a deadline the maker's signature commits to and no hash does (Verification Note 8). The
/// network is needed only to render the premium recipient as the `xch1…` address a maker recognises off
/// their own wallet.
pub fn preview_text(quote: &Quote, network: Network) -> Result<String> {
    let terms = &quote.terms;
    let derived = derived_ids(quote)?;

    let recipient = Address::new(
        terms.premium_recipient()?,
        network.address_prefix().to_string(),
    )
    .encode()
    .context("failed to render the premium recipient as an address")?;

    let underlying = amount_label(
        terms.underlying_amount,
        terms.backing_cat()?.map(|cat| cat.asset_id),
    );

    let strike = match terms.strike_type()? {
        OptionType::Xch { amount } => amount_label(amount, None),
        OptionType::Cat { asset_id, amount } => amount_label(amount, Some(asset_id)),
        // Unreachable: `Quote::new` validated the terms, and `strike_type` is what refused the
        // unsupported kinds. Named rather than guessed, in case that ever stops being true.
        _ => {
            return Err(
                SecError::terms("the terms carry a strike the preview cannot render").into(),
            );
        }
    };

    let premium = amount_label(terms.premium.amount, terms.premium_asset_id()?);

    // The floor is an amount the maker wrote as a decimal, so it gets both forms too — but only when
    // the draft set one: an omitted floor is zero (`fee_floor` defaults), and a `0 XCH` line would
    // read as a term the maker chose.
    let fee_floor = match terms.fee_floor {
        0 => String::new(),
        floor => format!("fee floor          {}\n", amount_label(floor, None)),
    };

    let creator = terms.creator_puzzle_hash()?;
    let creator = if creator == terms.maker_puzzle_hash()? {
        format!(
            "{} — your own puzzle hash: the underlying returns here on exercise",
            hex_bytes(creator.to_bytes())
        )
    } else {
        format!(
            "{} — the underlying returns here on exercise and the strike at expiry",
            hex_bytes(creator.to_bytes())
        )
    };

    Ok(format!(
        "locks              {underlying}\n\
         strike             {strike}, exercisable until {expiry}\n\
         take-by            {take_by} — signed, not hashed: it invalidates the offer, not the option\n\
         premium            {premium} -> {recipient}\n\
         {fee_floor}\
         creator            {creator}\n\
         launcher           {launcher}\n\
         option coin        {option}\n\
         premium payment    {payment}",
        expiry = rfc3339(terms.expiry_seconds),
        take_by = rfc3339(terms.take_by_seconds),
        // `Hex` is transparent over the `0x`-prefixed string the sidecar writes, so the preview prints
        // the same id a taker reads back.
        launcher = derived.launcher_id.0,
        option = derived.option_coin_id.0,
        payment = derived.premium_payment_hash.0,
    ))
}

/// What the option locks, in the asset's own base units.
fn underlying_label(quote: &Quote) -> Result<String> {
    let amount = quote.terms.underlying_amount;

    Ok(match quote.terms.backing_cat()? {
        Some(cat) => format!("{amount} of CAT {}", hex_bytes(cat.asset_id.to_bytes())),
        None => format!("{amount} mojos of XCH"),
    })
}

/// The strike the option is exercised for.
fn strike_label(strike: &OptionType) -> String {
    match strike {
        OptionType::Xch { amount } => format!("{amount} mojos of XCH"),
        OptionType::Cat { asset_id, amount } => {
            format!("{amount} of CAT {}", hex_bytes(asset_id.to_bytes()))
        }
        OptionType::RevocableCat {
            asset_id, amount, ..
        } => format!(
            "{amount} of revocable CAT {}",
            hex_bytes(asset_id.to_bytes())
        ),
        OptionType::Nft {
            launcher_id,
            amount,
            ..
        } => format!("{amount} for NFT {}", hex_bytes(launcher_id.to_bytes())),
    }
}

/// The premium the taker pays.
///
/// Amounts are printed in base units rather than as decimal XCH on purpose: the number a taker checks
/// is then the number the CLVM commits to, with no rounding in between.
fn premium_label(terms: &QuoteTerms) -> String {
    match &terms.premium.asset {
        PremiumAsset::Xch => format!("{} mojos of XCH", terms.premium.amount),
        PremiumAsset::Cat { asset_id, .. } => {
            format!("{} of CAT {}", terms.premium.amount, asset_id.0)
        }
    }
}

/// An amount in both forms: the decimal a maker reads, and the base units the CLVM commits to.
///
/// A CAT has no canonical decimal scale to trust (D2), so only its base units are shown — the one place
/// a preview deliberately shows fewer than two forms.
fn amount_label(amount: u64, cat_asset_id: Option<Bytes32>) -> String {
    match cat_asset_id {
        None => format!("{} XCH ({amount} mojos)", xch_decimal(amount)),
        Some(asset_id) => format!("{amount} of CAT {}", hex_bytes(asset_id.to_bytes())),
    }
}

/// A mojo amount in its decimal XCH form: `1_500_000_000_000` renders as `1.5`.
///
/// The inverse of `XchAmount::mojos`, and integer arithmetic for the same reason: twelve fraction
/// digits, trailing zeros trimmed, no float anywhere. A preview that rounded would show the maker a
/// number the CLVM does not commit to.
fn xch_decimal(mojos: u64) -> String {
    let whole = mojos / MOJOS_PER_XCH;
    let fraction = mojos % MOJOS_PER_XCH;

    if fraction == 0 {
        return whole.to_string();
    }

    let digits = format!("{fraction:012}");
    let trimmed = digits.trim_end_matches('0');

    format!("{whole}.{trimmed}")
}

/// What a re-quote did *not* do: the superseded offer file is still landable until its own deadline.
fn superseded_message(superseded: &SupersededQuote) -> String {
    match &superseded.offer_path {
        Some(path) => format!(
            "the previous offer {path} is still out there and stays landable until {} (no on-chain \
             invalidation)",
            superseded.take_by_seconds
        ),
        None => "no offer file had been written for it yet".to_string(),
    }
}

/// What the quote book says about this backing coin, if anything.
///
/// Read-only by construction: `QuoteBook::load` has no write path (`book.rs:99-128`), so warning is all
/// `prepare` can do. A coin that is already booked is exactly what `seal` refuses later, so the maker
/// hears about it before signing rather than after.
fn book_warning(book: &QuoteBook, quote: &Quote) -> Result<Option<String>, SecError> {
    let backing_coin_id = quote.terms.backing_coin()?.coin_id();

    let Some(entry) = book.get(backing_coin_id) else {
        return Ok(None);
    };

    Ok(Some(format!(
        "backing coin {} is already booked as {} ({}): a second landable offer over one coin is refused, \
         so `requote` or `retire` the booked quote first",
        hex_bytes(backing_coin_id.to_bytes()),
        entry.status,
        entry.offer_path.as_deref().unwrap_or("no offer file yet"),
    )))
}

/// The wall clock in unix seconds.
///
/// The one input the library refuses to read for itself (D3): `resolve` takes `now_seconds`, and this is
/// where the CLI supplies it. `--now` overrides it, which is what pins a relative deadline.
fn unix_now() -> Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is before the unix epoch; pass `--now <unix seconds>`")?;

    Ok(elapsed.as_secs())
}

/// Reads the maker's terms.
fn load_terms(path: &Path) -> Result<QuoteTerms> {
    let text = read_text(path, "terms")?;

    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse the terms at {}", path.display()))
}

/// Reads the maker's draft: a different document from the resolved terms by design (D1).
fn load_draft(path: &Path) -> Result<TermsDraft> {
    let text = read_text(path, "draft")?;

    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse the draft at {}", path.display()))
}

/// Reads a text file, naming what it was supposed to hold.
fn read_text(path: &Path, what: &str) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read the {what} at {}", path.display()))
}

/// Writes a text artifact with a trailing newline, so the file is a well-formed text file.
fn write_text(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, format!("{text}\n"))
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use securetheoption::{
        BackingAsset, BackingCatJson, CoinJson, LineageProofJson, Premium, StrikeType, XchAmount,
    };

    use super::*;

    /// A temp directory this test owns, keyed by name and process so parallel runs cannot collide.
    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("securetheoption-cli-{}-{name}", std::process::id()));

        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        dir
    }

    fn maker_key_hex() -> String {
        hex_bytes(SecretKey::from_seed(&[7; 32]).public_key().to_bytes())
    }

    fn maker_puzzle_hash() -> Bytes32 {
        StandardLayer::new(SecretKey::from_seed(&[7; 32]).public_key())
            .tree_hash()
            .into()
    }

    /// An XCH-backed quote carrying the economics the design's Desired End State shows.
    fn terms() -> QuoteTerms {
        QuoteTerms {
            maker_public_key: Hex::new(maker_key_hex()),
            creator_puzzle_hash: Hex::new(hex_bytes([9; 32])),
            underlying: BackingAsset::Xch {
                coin: CoinJson {
                    parent_coin_info: Hex::new(hex_bytes([1; 32])),
                    puzzle_hash: Hex::new(hex_bytes(maker_puzzle_hash().to_bytes())),
                    amount: 2_000_000_000_000,
                },
            },
            underlying_amount: 1_500_000_000_000,
            strike: StrikeType::Xch {
                amount: 2_000_000_000_000,
            },
            expiry_seconds: 1_780_000_000,
            take_by_seconds: 1_797_292_800,
            premium: Premium {
                recipient_puzzle_hash: Hex::new(hex_bytes([11; 32])),
                amount: 50_000_000_000,
                asset: PremiumAsset::Xch,
            },
            launcher_coin: None,
            fee_floor: 1_000_000_000,
        }
    }

    /// A CAT-backed quote: base units throughout, plus the XCH launcher coin a CAT needs.
    fn cat_terms() -> QuoteTerms {
        let asset_id = Bytes32::new([5; 32]);
        let cat_puzzle_hash: Bytes32 = CatInfo::new(asset_id, None, maker_puzzle_hash())
            .puzzle_hash()
            .into();
        let asset_id_hex = Hex::new(hex_bytes(asset_id.to_bytes()));

        QuoteTerms {
            maker_public_key: Hex::new(maker_key_hex()),
            creator_puzzle_hash: Hex::new(hex_bytes([9; 32])),
            underlying: BackingAsset::Cat {
                coin: CoinJson {
                    parent_coin_info: Hex::new(hex_bytes([1; 32])),
                    puzzle_hash: Hex::new(hex_bytes(cat_puzzle_hash.to_bytes())),
                    amount: 1_000,
                },
                backing_cat: BackingCatJson {
                    asset_id: asset_id_hex.clone(),
                    hidden_puzzle_hash: None,
                    lineage_proof: LineageProofJson {
                        parent_parent_coin_info: Hex::new(hex_bytes([2; 32])),
                        parent_inner_puzzle_hash: Hex::new(hex_bytes([3; 32])),
                        parent_amount: 1_000,
                    },
                },
            },
            underlying_amount: 500,
            strike: StrikeType::Cat {
                asset_id: asset_id_hex.clone(),
                amount: 2_500,
            },
            expiry_seconds: 1_780_000_000,
            take_by_seconds: 1_797_292_800,
            premium: Premium {
                recipient_puzzle_hash: Hex::new(hex_bytes([11; 32])),
                amount: 25,
                asset: PremiumAsset::Cat {
                    asset_id: asset_id_hex,
                    hidden_puzzle_hash: None,
                },
            },
            launcher_coin: Some(CoinJson {
                parent_coin_info: Hex::new(hex_bytes([6; 32])),
                puzzle_hash: Hex::new(hex_bytes(maker_puzzle_hash().to_bytes())),
                amount: 1,
            }),
            fee_floor: 0,
        }
    }

    /// A draft in the shape a maker writes: decimal amounts, a duration, a calendar instant.
    fn draft_document() -> serde_json::Value {
        serde_json::json!({
            "maker_public_key": maker_key_hex(),
            "underlying": {
                "kind": "xch",
                "coin": {
                    "parent_coin_info": hex_bytes([1; 32]),
                    "puzzle_hash": hex_bytes(maker_puzzle_hash().to_bytes()),
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
                "recipient": hex_bytes([11; 32]),
            },
        })
    }

    fn write_draft(dir: &Path, document: &serde_json::Value) -> PathBuf {
        let path = dir.join("draft.json");

        std::fs::write(
            &path,
            serde_json::to_string_pretty(document).expect("the draft serialises"),
        )
        .expect("the draft is writable");

        path
    }

    #[test]
    fn mojos_render_as_the_decimal_a_maker_wrote() -> anyhow::Result<()> {
        for (mojos, decimal) in [
            (0, "0"),
            (1, "0.000000000001"),
            (1_000_000_000, "0.001"),
            (50_000_000_000, "0.05"),
            (1_500_000_000_000, "1.5"),
            (2_000_000_000_000, "2"),
            (u64::MAX, "18446744.073709551615"),
        ] {
            assert_eq!(
                xch_decimal(mojos),
                decimal,
                "{mojos} mojos must render as {decimal}"
            );
        }

        // The round trip the decimal exists for: whatever it renders, the draft layer reads back, so a
        // preview can never show a number `create` would refuse.
        for mojos in [0, 1, 1_000_000_000, 1_500_000_000_000, u64::MAX] {
            assert_eq!(XchAmount::new(xch_decimal(mojos)).mojos("amount")?, mojos);
        }

        Ok(())
    }

    #[test]
    fn a_preview_shows_every_amount_in_both_forms() -> anyhow::Result<()> {
        let quote = Quote::new(terms())?;
        let text = preview_text(&quote, Network::Mainnet)?;

        // Verification Note 5: the decimal a maker writes and the mojos the CLVM commits to, together,
        // on every amount line.
        for expected in [
            "1.5 XCH (1500000000000 mojos)",
            "2 XCH (2000000000000 mojos)",
            "0.05 XCH (50000000000 mojos)",
            "0.001 XCH (1000000000 mojos)",
        ] {
            assert!(
                text.contains(expected),
                "`{expected}` missing from:\n{text}"
            );
        }

        Ok(())
    }

    #[test]
    fn the_take_by_line_says_it_is_not_hashed() -> anyhow::Result<()> {
        let quote = Quote::new(terms())?;
        let text = preview_text(&quote, Network::Mainnet)?;

        let line = |prefix: &str| {
            text.lines()
                .find(|line| line.starts_with(prefix))
                .unwrap_or_else(|| panic!("the preview names `{prefix}`:\n{text}"))
                .to_string()
        };

        // Verification Note 8: the take-by deadline lives in a spend solution, not in a hash, so the
        // preview must not present it like the expiry it sits beside.
        let take_by = line("take-by");

        assert!(take_by.contains("2026-12-15T00:00:00Z"), "{take_by}");
        assert!(take_by.contains("not hashed"), "{take_by}");

        let strike = line("strike");

        assert!(
            strike.contains("exercisable until 2026-05-28T20:26:40Z"),
            "{strike}"
        );
        assert!(!strike.contains("not hashed"), "{strike}");

        Ok(())
    }

    #[test]
    fn the_creator_line_names_a_supplied_creator_and_the_default_one() -> anyhow::Result<()> {
        let supplied = preview_text(&Quote::new(terms())?, Network::Mainnet)?;

        assert!(supplied.contains(&hex_bytes([9; 32])), "{supplied}");
        assert!(!supplied.contains("your own puzzle hash"), "{supplied}");

        // Omitted, D5's default is the maker's own standard-layer puzzle hash, and the preview says so
        // rather than presenting a derived address as a choice the maker made.
        let mut defaulted = terms();
        defaulted.creator_puzzle_hash = Hex::new(hex_bytes(maker_puzzle_hash().to_bytes()));

        let text = preview_text(&Quote::new(defaulted)?, Network::Mainnet)?;

        assert!(text.contains("your own puzzle hash"), "{text}");
        assert!(
            text.contains(&hex_bytes(maker_puzzle_hash().to_bytes())),
            "{text}"
        );

        Ok(())
    }

    #[test]
    fn the_json_preview_carries_the_terms_the_ids_and_the_commitment_tiers() -> anyhow::Result<()> {
        let quote = Quote::new(terms())?;
        let document = preview_json(&quote)?;

        assert_eq!(
            document["terms"]["expiry_seconds"],
            serde_json::json!(quote.terms.expiry_seconds)
        );
        assert_eq!(
            document["derived"]["launcher_id"].as_str(),
            Some(hex_bytes(quote.launcher_id.to_bytes()).as_str())
        );

        let tier = |name: &str| {
            document["commitment"][name]
                .as_array()
                .unwrap_or_else(|| panic!("`commitment.{name}` must be a list: {document}"))
                .clone()
        };

        // Verification Note 8, in the research's three tiers: the expiry is hash-committed, the take-by
        // and the premium are only signature-committed, and the fee floor binds nothing.
        let hashed = tier("hash_committed");

        assert!(
            hashed.contains(&serde_json::json!("expiry_seconds")),
            "{hashed:?}"
        );

        let signed = tier("signature_committed");

        assert!(
            signed.contains(&serde_json::json!("take_by_seconds")),
            "{signed:?}"
        );

        let informational = tier("informational");

        assert!(
            informational.contains(&serde_json::json!("fee_floor")),
            "{informational:?}"
        );

        // The tiers have to stay disjoint, or the preview tells the maker two things at once.
        for field in signed.iter().chain(informational.iter()) {
            assert!(!hashed.contains(field), "`{field}` is claimed by two tiers");
        }

        Ok(())
    }

    #[test]
    fn the_json_document_assembles_the_preview_and_the_dry_run() -> anyhow::Result<()> {
        let quote = Quote::new(terms())?;
        let document = preview_document(&quote, &["a warning".to_string()])?;

        // The verb's whole stdout payload in one value: the preview, the three claims about what
        // `prepare` did not do, and the warning the human path sends to stderr.
        assert_eq!(
            document["dry_run"]["maker_bundle_builds"],
            serde_json::json!(true)
        );
        assert_eq!(document["dry_run"]["signed"], serde_json::json!(false));
        assert_eq!(document["dry_run"]["booked"], serde_json::json!(false));
        assert_eq!(document["warnings"], serde_json::json!(["a warning"]));
        assert_eq!(
            document["derived"]["launcher_id"].as_str(),
            Some(hex_bytes(quote.launcher_id.to_bytes()).as_str())
        );

        // No warnings is an empty list, not a missing key, so a script reads one shape either way.
        assert_eq!(
            preview_document(&quote, &[])?["warnings"],
            serde_json::json!([])
        );

        Ok(())
    }

    #[test]
    fn a_cat_preview_stays_in_base_units() -> anyhow::Result<()> {
        let quote = Quote::new(cat_terms())?;
        let text = preview_text(&quote, Network::Mainnet)?;

        // D2: a CAT has no decimal scale to trust, so no CAT amount is ever rendered as a decimal — and
        // a quote with no XCH term shows no XCH amount at all.
        assert!(text.contains("500 of CAT"), "{text}");
        assert!(text.contains("2500 of CAT"), "{text}");
        assert!(text.contains("25 of CAT"), "{text}");
        assert!(!text.contains("XCH"), "{text}");

        Ok(())
    }

    #[test]
    fn the_premium_recipient_renders_with_the_network_prefix() -> anyhow::Result<()> {
        let quote = Quote::new(terms())?;

        for network in [Network::Mainnet, Network::Testnet11] {
            let expected =
                Address::new(Bytes32::new([11; 32]), network.address_prefix().to_string())
                    .encode()?;

            assert!(
                preview_text(&quote, network)?.contains(&expected),
                "the premium recipient must render as {expected}"
            );
        }

        Ok(())
    }

    #[test]
    fn prepare_resolves_a_draft_and_writes_only_the_terms() -> anyhow::Result<()> {
        let dir = temp_dir("prepare-writes");
        let draft = write_draft(&dir, &draft_document());
        let terms_path = dir.join("terms.json");

        prepare(&PrepareCommand {
            draft,
            output: Some(terms_path.clone()),
            network: Network::Mainnet,
            now: Some(1_700_000_000),
            book: dir.join("quotes.json"),
            json: false,
        })?;

        // What was written is the document `create --terms` reads, and it is the resolution of the draft
        // the maker wrote — not a preview, not a bundle.
        let written: QuoteTerms = serde_json::from_str(&std::fs::read_to_string(&terms_path)?)?;
        let expected = resolve(
            &load_draft(&dir.join("draft.json"))?,
            &ResolveContext {
                now_seconds: 1_700_000_000,
                address_prefix: "xch",
            },
        )?;

        assert_eq!(written, expected);
        assert_eq!(written.underlying_amount, 1_500_000_000_000);
        assert_eq!(written.expiry_seconds, 1_700_000_000 + 2_592_000);
        assert_eq!(written.take_by_seconds, 1_797_292_800);

        Ok(())
    }

    #[test]
    fn prepare_never_writes_the_quote_book() -> anyhow::Result<()> {
        let dir = temp_dir("prepare-book");
        let draft = write_draft(&dir, &draft_document());
        let book = dir.join("quotes.json");

        // Twice over the same backing coin: a second preview is not a second commit.
        for _ in 0..2 {
            prepare(&PrepareCommand {
                draft: draft.clone(),
                output: None,
                network: Network::Mainnet,
                now: Some(1_700_000_000),
                book: book.clone(),
                json: true,
            })?;
        }

        // Verification Note 9: the book is read, never written.
        assert!(!book.exists(), "prepare must not create the quote book");

        Ok(())
    }

    #[test]
    fn book_warning_names_an_already_booked_coin() -> anyhow::Result<()> {
        let dir = temp_dir("book-warning");
        let book_path = dir.join("quotes.json");
        let quote = Quote::new(terms())?;

        assert_eq!(book_warning(&QuoteBook::load(&book_path)?, &quote)?, None);

        let mut book = QuoteBook::load(&book_path)?;
        book.create(&quote)?;

        let warning =
            book_warning(&book, &quote)?.expect("a booked backing coin is worth a warning");
        let coin_id = hex_bytes(quote.terms.backing_coin()?.coin_id().to_bytes());

        // The warning has to say the thing `seal` would say later, and which verb changes it.
        assert!(warning.contains("already booked"), "{warning}");
        assert!(warning.contains(&coin_id), "{warning}");
        assert!(warning.contains("quoted"), "{warning}");
        assert!(warning.contains("requote"), "{warning}");

        Ok(())
    }

    #[test]
    fn a_bad_draft_fails_before_anything_is_previewed() -> anyhow::Result<()> {
        let dir = temp_dir("bad-draft");
        let mut document = draft_document();
        document["expiry"] = serde_json::json!("30x");

        let draft = write_draft(&dir, &document);
        let terms_path = dir.join("terms.json");

        let error = prepare(&PrepareCommand {
            draft,
            output: Some(terms_path.clone()),
            network: Network::Mainnet,
            now: Some(1_700_000_000),
            book: dir.join("quotes.json"),
            json: false,
        })
        .unwrap_err();

        // Verification Note 12: a bad draft names the field the maker can see, in a chain a caller can
        // read, and the run writes nothing.
        let chain = format!("{error:#}");

        assert!(chain.contains("expiry"), "{chain}");
        assert!(chain.contains("resolved"), "{chain}");
        assert!(!terms_path.exists(), "a failed prepare must write nothing");

        Ok(())
    }
}

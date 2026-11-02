mod args;
mod commands;
mod json;

use anyhow::Result;
use clap::Parser;

use crate::args::{Command, QuoteCommand};

/// Every command is offline, so `main` is synchronous and no async runtime is linked in
/// (Verification Note 10).
fn main() -> Result<()> {
    match Command::parse() {
        Command::Quote(QuoteCommand::Prepare(args)) => commands::prepare(&args),
        Command::Quote(QuoteCommand::Create(args)) => commands::create(&args),
        Command::Quote(QuoteCommand::Seal(args)) => commands::seal(&args),
        Command::Quote(QuoteCommand::Verify(args)) => commands::verify(&args),
        Command::Quote(QuoteCommand::List(args)) => commands::list(&args),
        Command::Quote(QuoteCommand::Requote(args)) => commands::requote(&args),
        Command::Quote(QuoteCommand::Retire(args)) => commands::retire(&args),
    }
}

mod crypto_engine;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Target {
    Win,
    Web,
    Android,
    Ios,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Level {
    Standard,
    Paranoid,
}

#[derive(Debug, Parser)]
#[command(name = "aegisforge", version, about = "File protection prototype using AES-256-GCM")]
struct Args {
    /// Input file to protect
    #[arg(short, long)]
    input: PathBuf,

    /// Output encrypted file
    #[arg(short, long)]
    output: PathBuf,

    /// Intended target platform (metadata only in this prototype)
    #[arg(short, long, value_enum)]
    target: Target,

    /// Protection profile (metadata only in this prototype)
    #[arg(short, long, value_enum, default_value_t = Level::Standard)]
    level: Level,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.input == args.output {
        bail!("Input and output paths must be different.");
    }
    if args.output.exists() {
        bail!("Output already exists; refusing to overwrite it.");
    }

    let key_hex = std::env::var("AEGISFORGE_KEY_HEX")
        .context("Set AEGISFORGE_KEY_HEX to a 64-character hex-encoded 32-byte key.")?;
    let key = hex::decode(key_hex.trim()).context("AEGISFORGE_KEY_HEX is not valid hex.")?;
    if key.len() != 32 {
        bail!("AEGISFORGE_KEY_HEX must decode to exactly 32 bytes.");
    }

    let input = fs::read(&args.input)
        .with_context(|| format!("Could not read input file: {}", args.input.display()))?;
    let encrypted = crypto_engine::encrypt(&input, &key)?;
    fs::write(&args.output, encrypted)
        .with_context(|| format!("Could not write output file: {}", args.output.display()))?;

    println!(
        "Protected {} -> {} (target: {:?}, level: {:?})",
        args.input.display(),
        args.output.display(),
        args.target,
        args.level
    );
    println!("Note: target and level are metadata only; platform-specific transforms are not implemented yet.");
    Ok(())
}

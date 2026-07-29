use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

mod capture;
mod xml_writer;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "pcapxml",
    about = "Extract packets from a .pcapng file and convert them to structured XML",
    version
)]
struct Cli {
    /// Input .pcapng file
    #[arg(short, long, value_name = "FILE")]
    file: PathBuf,

    /// Select a single packet by its frame number (1-based).
    /// Translates to the display filter: frame.number == N
    #[arg(short = 'n', long = "packet", value_name = "N")]
    packet_number: Option<u32>,

    /// Wireshark display filter (e.g. "tcp", "ip.addr == 10.0.0.1").
    /// Combined with --packet when both are given.
    #[arg(short = 'Y', long = "filter", value_name = "FILTER")]
    filter: Option<String>,

    /// Write XML to FILE instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Combine --packet and --filter into a single tshark display filter.
    let display_filter = build_filter(cli.packet_number, cli.filter.as_deref());

    let packets =
        capture::read_packets(&cli.file, display_filter.as_deref()).context("Reading pcapng")?;

    if packets.is_empty() {
        eprintln!("No packets matched the given criteria.");
        return Ok(());
    }

    let xml = xml_writer::packets_to_xml(&packets).context("Generating XML")?;

    match &cli.output {
        Some(path) => {
            fs::write(path, xml.as_bytes()).context("Writing output file")?;
            eprintln!("Wrote {} packet(s) to {}", packets.len(), path.display());
        }
        None => print!("{xml}"),
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_filter(packet_number: Option<u32>, display_filter: Option<&str>) -> Option<String> {
    match (packet_number, display_filter) {
        (Some(n), Some(f)) => Some(format!("(frame.number == {n}) && ({f})")),
        (Some(n), None) => Some(format!("frame.number == {n}")),
        (None, Some(f)) => Some(f.to_string()),
        (None, None) => None,
    }
}

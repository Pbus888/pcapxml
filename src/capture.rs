use anyhow::{Context, Result};
use rtshark::RTSharkBuilder;
use std::path::Path;

// ── Data model ──────────────────────────────────────────────────────────────

/// A single protocol field (one row in Wireshark's packet details).
pub struct Field {
    /// tshark internal name, e.g. "ip.src"
    pub name: String,
    /// Raw / hex value as reported by tshark, e.g. "c0a80101"
    pub value: String,
    /// Human-readable display string, e.g. "192.168.1.1"
    pub display: String,
}

/// One protocol layer, e.g. "eth", "ip", "tcp", "http".
pub struct Layer {
    pub name: String,
    pub fields: Vec<Field>,
}

/// All layers for one packet.
pub struct Packet {
    /// 1-based index within the filtered result set.
    pub number: u32,
    pub layers: Vec<Layer>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Read packets from *path*, applying *display_filter* if provided.
///
/// The filter is a standard Wireshark display filter, e.g.:
///   "frame.number == 3"
///   "tcp && ip.addr == 192.168.1.1"
pub fn read_packets(path: &Path, display_filter: Option<&str>) -> Result<Vec<Packet>> {
    let path_str = path.to_str().context("File path contains invalid UTF-8")?;

    let mut builder = RTSharkBuilder::builder().input_path(path_str);

    if let Some(filter) = display_filter {
        builder = builder.display_filter(filter);
    }

    let mut rtshark = builder
        .spawn()
        .context("Failed to start tshark. Is Wireshark/tshark installed and on PATH?")?;

    let mut packets = Vec::new();
    let mut seq = 0u32;

    loop {
        match rtshark.read() {
            Err(e) => {
                eprintln!("Warning: {e}");
            }
            Ok(rtshark::Output::EOF) => break,
            Ok(rtshark::Output::Packet(packet)) => {
                seq += 1;
                packets.push(dissect(seq, packet));
            }
        }
    }

    Ok(packets)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn dissect(number: u32, packet: rtshark::Packet) -> Packet {
    let layers = packet
        .iter()
        .map(|layer| Layer {
            name: layer.name().to_string(),
            fields: layer
                .iter()
                .map(|m| Field {
                    name: m.name().to_string(),
                    value: m.value().to_string(),
                    display: m.display().to_string(),
                })
                .collect(),
        })
        .collect();

    Packet { number, layers }
}

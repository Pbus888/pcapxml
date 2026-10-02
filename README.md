# pcapxml

**A PCAP/PCAPNG-to-XML converter written in Rust.**

`pcapxml` converts network packet captures into structured XML, making captured protocol data easier to inspect, process, and integrate into other tools and workflows.

## Features

- **PCAP/PCAPNG input:** Work with packet capture files.
- **XML output:** Export decoded packet data in a structured format.
- **Packet selection:** Select a specific packet for inspection.
- **Display filtering:** Filter packets before processing.
- **Telecom protocol analysis:** Support workflows involving GTP signaling and telecom packet captures, where implemented.
- **CLI interface:** Convert captures directly from the terminal.

## Use Cases

- Inspecting network traffic from packet captures.
- Extracting protocol fields for further analysis.
- Preparing captured data for automated processing.
- Working with telecom signaling traces and GTP traffic.

## Requirements

- Rust and Cargo
- `tshark` installed and available in your `PATH`, if required by your current implementation.

## Installation

Clone the repository:

```bash
git clone https://github.com/Pbus888/pcapxml.git
cd pcapxml
```

Build the project:

```bash
cargo build --release
```

## Usage

Convert a capture file to XML:

```bash
cargo run --release -- -f capture.pcapng
```

Select a packet:

```bash
cargo run --release -- -f capture.pcapng -n 10
```

Apply a display filter:

```bash
cargo run --release -- -f capture.pcapng -Y "gtp"
```

Specify an output file:

```bash
cargo run --release -- -f capture.pcapng -o output.xml
```

Check the available options:

```bash
cargo run --release -- --help
```

*Adjust these examples to match the exact arguments and behavior supported by your current version.*

## How It Works

1. Load a PCAP or PCAPNG capture.
2. Decode packet information using the supported parsing backend.
3. Process the decoded data and apply any requested filters.
4. Export the resulting data as XML.

## Project Structure

Update this section to match the actual repository layout.

- `core/` - Core data models and shared functionality.
- `ingest/` - Capture input and packet ingestion.
- `pipeline/` - Processing and transformation.
- `export/` - XML generation and output.

## Contributing

Contributions, bug reports, and feature suggestions are welcome. Please open an issue to discuss substantial changes before submitting a pull request.

## License

See [LICENSE](LICENSE) for the project's license terms.

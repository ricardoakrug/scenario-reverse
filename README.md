# Scenario Classic-NET RS-485 Reverse Engineering

Reverse-engineer the proprietary **Classic-NET** bus protocol used by [Scenario Automacao](https://scenarioautomacao.com.br/) home automation modules — without the IFSEI controller.

## Background

Scenario Classic is a Brazilian home automation system that uses a **proprietary RS-485 bus** (Classic-NET) to connect dimmers, relays, keypads, and a central IFSEI controller. The only documented interface is the Telnet TCP protocol exposed by the IFSEI — but if you don't have an IFSEI (or it dies), you're locked out.

This project sniffs the raw RS-485 bus to decode the binary protocol directly, enabling future direct control of modules from Home Assistant or any other platform.

### Target Hardware

| Module | Model | Function |
|--------|-------|----------|
| Dimmer (LED) | **MDM8** (ST-MPT8-LED) | 8-channel dimmable lighting (200W/ch) |
| Relay (AC) | **RDM8-AC** (ST-MPR8-AC) | 8-channel dry-contact relays (motors, AC loads) |
| Relay (DC) | **RDM8-DC** (ST-MPR8-BC) | 8-channel low-current independent relays |

### Sniffing Setup

```
Scenario Keypad ──┐
                  │  Classic-NET (RS-485 bus, 4-wire)
MDM8 / RDM8 ─────┼──────────────────── A/B ── USB-to-RS-485 ── Mac/PC
                  │                            (FT232RL + 75176)
Other modules ────┘
```

The USB adapter connects in **listen-only mode** (no transmission) — it passively taps the A/B differential pair to capture all traffic.

## Requirements

- Python 3.10+
- USB-to-RS-485 adapter (FT232RL, CH340, or CP2102 based)

```bash
pip install pyserial
```

## Quick Start

```bash
# Full wizard — walks through all 4 phases
python3 sniff_classicnet.py

# Resume a previous session
python3 sniff_classicnet.py --resume sessions/2026-03-16_143022/

# Jump to a specific phase
python3 sniff_classicnet.py --phase 3 --resume sessions/2026-03-16_143022/

# Re-run analysis on existing captures
python3 sniff_classicnet.py --analyze sessions/2026-03-16_143022/

# Skip port auto-detection
python3 sniff_classicnet.py --port /dev/cu.usbserial-XYZ
```

## How It Works

The wizard walks through 4 phases:

### Phase 1: Setup

- Auto-detects USB-to-serial adapters (`tty.usbserial-*`, FT232RL, CH340, CP210x)
- Lets you confirm or manually specify the port
- Collects module inventory (pre-filled: 3x MDM8, 1x RDM8-AC, 1x RDM8-DC)
- Creates a timestamped session directory

### Phase 2: Baud Rate & Serial Parameter Detection

Scans combinations of baud rates and serial parameters to find the correct bus settings.

**Primary scan:** 5 baud rates x 6 param combos = 30 tests (~90 seconds)
- Bauds: `9600, 19200, 38400, 57600, 115200`
- Params: `8N1, 8E1, 8O1, 8N2, 7E1, 7O1`

**Extended scan** (if primary finds nothing): +10 baud rates x 6 params = 60 more tests

**Why not use existing baud detectors?** Tools like [devttys0/baudrate](https://github.com/devttys0/baudrate) use ASCII heuristics (vowels, whitespace) that fail on binary protocols. This scanner uses binary-aware scoring:

| Heuristic | What it measures |
|-----------|-----------------|
| Shannon entropy | Structured binary data = 3.0–6.5 (garbage ≈ 8.0) |
| Packet length consistency | Same-length packets suggest correct framing |
| Consistent start byte | Common header byte across packets |
| Chi-squared distribution | Deviation from uniform byte distribution |
| Framing error count | Wrong params produce UART framing errors |
| Printable ratio | Fallback: catches text-based protocols |

You'll press keypad buttons during the scan to generate traffic. Results are ranked in a table and you pick the winner.

### Phase 3: Guided Capture

Interactive, step-by-step capture of 18 known actions:

| # | Action | Purpose |
|---|--------|---------|
| 1 | Idle baseline (30s) | Identify periodic polling / heartbeat packets |
| 2–5 | MDM8 #1 CH1/CH2 ON/OFF | Basic command structure |
| 6–8 | MDM8 #1 CH1 DIM 25/50/100% | Intensity byte identification |
| 9–12 | MDM8 #2, #3 CH1 ON/OFF | Module address byte identification |
| 13–15 | RDM8-AC Motor OPEN/CLOSE/STOP | Motor relay commands |
| 16–18 | RDM8-DC Motor OPEN/CLOSE/STOP | DC relay commands |

Each capture:
1. You press Enter when ready
2. Pre-action buffer (500ms) starts recording
3. You perform the action, press Enter
4. Post-action buffer (1000ms) captures response
5. Packets displayed, saved to JSON + raw `.bin`

Supports **skip**, **repeat**, **notes**, and **session resume**.

### Phase 4: Systematic Test Matrix

Generates a full capture matrix from your module inventory:

- **Quick mode:** 2 channels per module (CH1 + CH8) x all operations (~40 captures)
- **Full mode:** All 8 channels x all operations x all modules (~300 captures)

Progress bar, pause/resume, per-capture save.

### Analysis

Runs automatically after Phase 3 and Phase 4 (or standalone with `--analyze`):

- **Unique packets** — deduplicated with occurrence counts and action contexts
- **Byte-position analysis** — for each position in same-length packets: unique values, correlation with module index / channel / action type, flags constant vs. variable vs. possible checksum positions
- **Idle traffic patterns** — interval statistics, repeating packets
- **Checksum hypothesis testing** — tries XOR, SUM mod 256, 2's complement, CRC-8 (poly 0x07), CRC-16/Modbus on every packet; reports match ratios
- **Telnet protocol cross-reference** — notes mapping known Telnet commands (`$DxxZyyL`) to likely byte positions

## Session Data Structure

```
sessions/
  2026-03-16_143022/
    session.json                # port, serial config, modules, phases completed
    phase2_baud_scan.json       # all combos with scores, selected winner
    phase3_guided/
      captures.json             # labeled captures with packets, timestamps
      raw/                      # binary dumps per capture
        001_idle-0_ch0_idle.bin
        002_mdm8-1_ch1_on.bin
        ...
    phase4_matrix/
      captures.json
      raw/
    analysis/
      packet_summary.json       # unique packets, byte-position analysis, checksums
```

### Capture Entry Schema

```json
{
  "id": 2,
  "label": "MDM8 #1 CH1 ON",
  "module_type": "MDM8",
  "module_index": 1,
  "channel": 1,
  "action": "on",
  "timestamp_start": "2026-03-16T14:30:45.123",
  "timestamp_action": "2026-03-16T14:30:45.623",
  "timestamp_end": "2026-03-16T14:30:47.890",
  "packets": [
    {
      "hex": "aa01080100ff55",
      "length": 7,
      "gap_before_ms": 12.345
    }
  ],
  "raw_file": "raw/002_mdm8-1_ch1_on.bin",
  "notes": ""
}
```

## Packet Framing Strategy

Since we don't know start/end markers, packets are framed by **inter-byte gap detection**:

1. Background thread reads bytes one at a time with `time.perf_counter()` timestamps
2. Gap threshold = 3x byte transmission time (e.g., 3.1ms at 9600 8N1)
3. Bytes arriving within the threshold = same packet
4. Gap exceeding the threshold = new packet boundary

This works because RS-485 bus protocols typically have idle gaps between frames that are significantly longer than inter-byte gaps within a frame.

## Telnet Protocol Reference (Rosetta Stone)

The IFSEI controller's documented Telnet protocol provides known semantics to correlate with raw bus data:

| Command | Format | Meaning |
|---------|--------|---------|
| Switch ON | `$DxxZyyL` | Module xx, zone yy, load on |
| Switch OFF | `$DxxZyyD` | Module xx, zone yy, load off |
| Dim | `$DxxZyyiiTss` | Intensity ii (00–63), speed ss |
| State push | `*DxxZyyii` | Event: module xx, zone yy at intensity ii |

Where `xx` = module address (decimal), `yy` = zone/channel (decimal).

The bus protocol likely encodes the same module/zone/action information in binary — the analysis engine looks for byte positions that correlate with these known variables.

## Adapter Wiring

```
Classic-NET 4-wire cable:
  Wire 1 (Power +)  ── not connected to adapter
  Wire 2 (Power -)  ── not connected to adapter
  Wire 3 (Data A+)  ── RS-485 adapter A
  Wire 4 (Data B-)  ── RS-485 adapter B

Optional: connect adapter GND to power ground for signal reference
```

**Important:** The adapter is passive (listen-only). Do not enable the transmitter — you risk bus collisions with the IFSEI or modules.

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| No serial ports detected | Adapter not plugged in or no driver | Install FTDI/CH340 driver, check `ls /dev/cu.usbserial*` |
| Phase 2 finds nothing | No bus traffic during scan | Press keypad buttons repeatedly during the scan |
| All combos score 0 | Adapter not connected to A/B lines | Check wiring, verify bus is powered |
| High framing errors everywhere | A/B lines swapped | Swap the two data wires |
| Packets but entropy ~8.0 | Wrong baud rate (reading garbage) | Try extended scan or manual baud entry |
| Inconsistent packet lengths | Gap threshold too tight/loose | Adjust `GAP_MULTIPLIER` constant in script |

## Next Steps

After successful captures, the `analysis/packet_summary.json` file is designed to be fed to Claude or another LLM for deeper protocol analysis:

1. Identify frame structure (header, address, command, data, checksum)
2. Map byte values to module addresses and channel numbers
3. Decode dimmer intensity encoding (likely 0x00–0x3F matching Telnet's 00–63)
4. Verify checksum algorithm
5. Build a protocol spec document
6. Implement a Home Assistant custom component that speaks Classic-NET directly over RS-485

## Legal

**Methodology.** This project uses passive observation of electrical signals (RS-485 differential voltage levels) on hardware owned by the user. No software is copied, decompiled, or disassembled. No access controls, encryption, or technological protection measures are circumvented.

**Purpose.** Interoperability with [Home Assistant](https://www.home-assistant.io/) and other open home automation platforms.

| Jurisdiction | Legal Basis |
|-------------|-------------|
| **Brazil** | Lei 9.609/98 Art. 6 — functional similarity developed through independent effort is not infringement |
| **US** | DMCA §1201(f) interoperability exception; no TPM is circumvented; passive signal observation is not "access" |
| **EU** | Directive 2009/24/EC Art. 5(3) (observation of behavior) + Art. 6 (decompilation for interop) + Art. 8 (contrary EULA clauses are void) |

**Precedent.** No vendor has successfully challenged passive protocol reverse engineering for interoperability. Notable examples: OpenZWave, Lutron Caseta/RadioRA 2, SMA solar inverters.

> **Disclaimer:** This is not legal advice. Consult a qualified attorney for your specific situation.

## License

MIT License — see [LICENSE](LICENSE). Not affiliated with Scenario Automacao.

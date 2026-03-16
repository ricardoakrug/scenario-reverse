#!/usr/bin/env python3
"""
Scenario Classic-NET RS-485 Bus Sniffing Wizard
================================================
Reverse-engineer the proprietary Classic-NET bus protocol used by Scenario
Automacao home automation modules (MDM8 dimmers, RDM8 relays, etc.).

Walks through 4 phases:
  1. Setup         — detect serial port, collect module inventory, create session
  2. Baud Detect   — scan baud rates & serial params with binary-aware scoring
  3. Guided Capture — interactive step-by-step capture of known actions
  4. Test Matrix    — systematic full-matrix capture across all modules/channels

Only dependency: pyserial (pip install pyserial)
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("ERROR: pyserial is required. Install with: pip install pyserial")
    sys.exit(1)


# ── Constants ────────────────────────────────────────────────────────────────

PRIMARY_BAUDS = [9600, 19200, 38400, 57600, 115200]
EXTENDED_BAUDS = [4800, 2400, 1200, 14400, 28800, 76800, 230400, 250000, 460800, 500000]

SERIAL_PARAMS = [
    (8, "N", 1),
    (8, "E", 1),
    (8, "O", 1),
    (8, "N", 2),
    (7, "E", 1),
    (7, "O", 1),
]

PARITY_MAP = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD}
STOPBITS_MAP = {1: serial.STOPBITS_ONE, 2: serial.STOPBITS_TWO}

DEFAULT_LISTEN_WINDOW = 3.0  # seconds per baud/param combo
GAP_MULTIPLIER = 3.0  # inter-byte gap = N × byte_time
MIN_PACKETS_FOR_SCORE = 3

# Known Telnet protocol as Rosetta Stone reference
# $DxxZyyL = ON, $DxxZyyD = OFF, $DxxZyyiiTss = dim
# *DxxZyyii = state push from IFSEI
TELNET_REFERENCE = {
    "on": "$D{module:02d}Z{zone:02d}L",
    "off": "$D{module:02d}Z{zone:02d}D",
    "dim": "$D{module:02d}Z{zone:02d}{intensity:02d}T{speed:02d}",
    "state_push": "*D{module:02d}Z{zone:02d}{intensity:02d}",
}

# Default module inventory
DEFAULT_MODULES = [
    {"type": "MDM8", "index": 1, "label": "MDM8 #1", "channels": 8, "operations": ["on", "off", "dim"]},
    {"type": "MDM8", "index": 2, "label": "MDM8 #2", "channels": 8, "operations": ["on", "off", "dim"]},
    {"type": "MDM8", "index": 3, "label": "MDM8 #3", "channels": 8, "operations": ["on", "off", "dim"]},
    {"type": "RDM8-AC", "index": 1, "label": "RDM8-AC #1", "channels": 8, "operations": ["open", "close", "stop"]},
    {"type": "RDM8-DC", "index": 1, "label": "RDM8-DC #1", "channels": 8, "operations": ["open", "close", "stop"]},
]


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class SerialConfig:
    port: str
    baudrate: int = 9600
    bytesize: int = 8
    parity: str = "N"
    stopbits: int = 1

    def label(self) -> str:
        return f"{self.baudrate} {self.bytesize}{self.parity}{self.stopbits}"

    def byte_time(self) -> float:
        """Time in seconds to transmit one byte (start + data + parity + stop)."""
        bits = 1 + self.bytesize + (1 if self.parity != "N" else 0) + self.stopbits
        return bits / self.baudrate


@dataclass
class Packet:
    timestamp: float  # time.perf_counter() of first byte
    data: bytes = b""
    gap_before_ms: Optional[float] = None

    @property
    def hex(self) -> str:
        return self.data.hex()

    @property
    def length(self) -> int:
        return len(self.data)

    def to_dict(self) -> dict:
        return {
            "hex": self.hex,
            "length": self.length,
            "gap_before_ms": round(self.gap_before_ms, 3) if self.gap_before_ms is not None else None,
        }


@dataclass
class CaptureEntry:
    id: int
    label: str
    module_type: str = ""
    module_index: int = 0
    channel: int = 0
    action: str = ""
    timestamp_start: str = ""
    timestamp_action: str = ""
    timestamp_end: str = ""
    packets: list = field(default_factory=list)
    raw_file: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["packets"] = [p if isinstance(p, dict) else p.to_dict() for p in self.packets]
        return d


@dataclass
class BaudScanResult:
    baudrate: int
    bytesize: int
    parity: str
    stopbits: int
    score: float
    entropy: float
    packet_count: int
    consistent_lengths: bool
    consistent_start_byte: bool
    framing_errors: int
    chi_squared: float
    total_bytes: int
    sample_hex: str = ""

    def label(self) -> str:
        return f"{self.baudrate} {self.bytesize}{self.parity}{self.stopbits}"

    def to_dict(self) -> dict:
        return asdict(self)


# ── Capture Session ──────────────────────────────────────────────────────────

class CaptureSession:
    """Manages session directory and persistent JSON state."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.session_file = base_dir / "session.json"
        self.state: dict = {}

    @classmethod
    def create(cls, parent: Path) -> "CaptureSession":
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        session_dir = parent / "sessions" / ts
        session_dir.mkdir(parents=True, exist_ok=True)
        session = cls(session_dir)
        session.state = {
            "created": ts,
            "phases_completed": [],
            "port": "",
            "serial_config": {},
            "modules": [],
        }
        session.save()
        return session

    @classmethod
    def load(cls, session_dir: Path) -> "CaptureSession":
        session = cls(session_dir)
        if session.session_file.exists():
            with open(session.session_file) as f:
                session.state = json.load(f)
        else:
            raise FileNotFoundError(f"No session.json in {session_dir}")
        return session

    def save(self):
        with open(self.session_file, "w") as f:
            json.dump(self.state, f, indent=2)

    def ensure_subdir(self, *parts: str) -> Path:
        d = self.base_dir / Path(*parts)
        d.mkdir(parents=True, exist_ok=True)
        return d


# ── Serial Sniffer (Background Reader) ──────────────────────────────────────

class SerialSniffer:
    """
    Background thread that reads bytes from the serial port and frames them
    into packets using inter-byte gap detection.
    """

    def __init__(self, config: SerialConfig, gap_threshold: Optional[float] = None):
        self.config = config
        self.gap_threshold = gap_threshold or (config.byte_time() * GAP_MULTIPLIER)
        self._ser: Optional[serial.Serial] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._packets: list[Packet] = []
        self._current_packet: Optional[Packet] = None
        self._last_byte_time: float = 0.0
        self._raw_bytes: bytearray = bytearray()
        self._raw_timestamps: list[float] = []
        self._framing_errors: int = 0

    def start(self):
        self._ser = serial.Serial(
            port=self.config.port,
            baudrate=self.config.baudrate,
            bytesize=self.config.bytesize,
            parity=PARITY_MAP[self.config.parity],
            stopbits=STOPBITS_MAP[self.config.stopbits],
            timeout=0.01,
        )
        self._running = True
        self._packets = []
        self._current_packet = None
        self._last_byte_time = 0.0
        self._raw_bytes = bytearray()
        self._raw_timestamps = []
        self._framing_errors = 0
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()

    def stop(self) -> list[Packet]:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        # Finalize any in-progress packet
        with self._lock:
            if self._current_packet and self._current_packet.data:
                self._packets.append(self._current_packet)
                self._current_packet = None
        if self._ser and self._ser.is_open:
            self._ser.close()
        return list(self._packets)

    def get_packets(self) -> list[Packet]:
        with self._lock:
            return list(self._packets)

    def get_packets_since(self, t: float) -> list[Packet]:
        with self._lock:
            return [p for p in self._packets if p.timestamp >= t]

    def get_raw_bytes(self) -> bytes:
        with self._lock:
            return bytes(self._raw_bytes)

    @property
    def framing_errors(self) -> int:
        return self._framing_errors

    def clear(self):
        with self._lock:
            self._packets = []
            self._current_packet = None
            self._raw_bytes = bytearray()
            self._raw_timestamps = []

    def _reader_loop(self):
        while self._running:
            try:
                data = self._ser.read(1)
                if not data:
                    continue
                now = time.perf_counter()
                with self._lock:
                    self._raw_bytes.extend(data)
                    self._raw_timestamps.append(now)

                    if self._last_byte_time == 0.0:
                        # First byte ever
                        self._current_packet = Packet(timestamp=now, data=data, gap_before_ms=None)
                    else:
                        gap = now - self._last_byte_time
                        if gap > self.gap_threshold:
                            # Gap detected → finalize current, start new
                            if self._current_packet and self._current_packet.data:
                                self._packets.append(self._current_packet)
                            self._current_packet = Packet(
                                timestamp=now,
                                data=data,
                                gap_before_ms=gap * 1000.0,
                            )
                        else:
                            # Same packet
                            if self._current_packet:
                                self._current_packet.data += data
                            else:
                                self._current_packet = Packet(timestamp=now, data=data)

                    self._last_byte_time = now

            except serial.SerialException:
                self._framing_errors += 1
            except Exception:
                if self._running:
                    time.sleep(0.001)


# ── Baud Rate Detector ──────────────────────────────────────────────────────

class BaudDetector:
    """Phase 2: Scan baud rates and serial parameters with binary-aware scoring."""

    def __init__(self, port: str, listen_window: float = DEFAULT_LISTEN_WINDOW):
        self.port = port
        self.listen_window = listen_window

    def scan(self, bauds: list[int], params: list[tuple], progress_cb=None) -> list[BaudScanResult]:
        results = []
        total = len(bauds) * len(params)
        idx = 0

        for baud in bauds:
            for bytesize, parity, stopbits in params:
                idx += 1
                label = f"{baud} {bytesize}{parity}{stopbits}"
                if progress_cb:
                    progress_cb(idx, total, label)

                config = SerialConfig(
                    port=self.port,
                    baudrate=baud,
                    bytesize=bytesize,
                    parity=parity,
                    stopbits=stopbits,
                )

                try:
                    result = self._test_combo(config)
                    results.append(result)
                except (serial.SerialException, OSError) as e:
                    results.append(BaudScanResult(
                        baudrate=baud, bytesize=bytesize, parity=parity,
                        stopbits=stopbits, score=-1, entropy=0, packet_count=0,
                        consistent_lengths=False, consistent_start_byte=False,
                        framing_errors=0, chi_squared=0, total_bytes=0,
                        sample_hex=f"ERROR: {e}",
                    ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def _test_combo(self, config: SerialConfig) -> BaudScanResult:
        sniffer = SerialSniffer(config)
        sniffer.start()
        time.sleep(self.listen_window)
        packets = sniffer.stop()
        raw = sniffer.get_raw_bytes()

        total_bytes = len(raw)
        framing_errors = sniffer.framing_errors

        if total_bytes < 4:
            return BaudScanResult(
                baudrate=config.baudrate, bytesize=config.bytesize,
                parity=config.parity, stopbits=config.stopbits,
                score=0, entropy=0, packet_count=len(packets),
                consistent_lengths=False, consistent_start_byte=False,
                framing_errors=framing_errors, chi_squared=0,
                total_bytes=total_bytes,
            )

        entropy = self._shannon_entropy(raw)
        chi_sq = self._chi_squared(raw)
        consistent_lengths = self._check_consistent_lengths(packets)
        consistent_start = self._check_consistent_start_byte(packets)

        # Binary scoring heuristic
        score = 0.0

        # Entropy: structured binary data typically 3.0-6.5
        if 3.0 <= entropy <= 6.5:
            score += 30.0
        elif 2.0 <= entropy <= 7.0:
            score += 15.0
        elif entropy > 7.5:
            score -= 10.0  # Likely garbage / wrong baud

        # Packet count (more packets = more likely correct)
        if len(packets) >= MIN_PACKETS_FOR_SCORE:
            score += min(20.0, len(packets) * 2.0)

        # Consistent packet lengths
        if consistent_lengths and len(packets) >= MIN_PACKETS_FOR_SCORE:
            score += 20.0

        # Consistent start byte
        if consistent_start and len(packets) >= MIN_PACKETS_FOR_SCORE:
            score += 20.0

        # Chi-squared: lower deviation from structured = better
        # For structured data, chi-sq should be high (non-uniform)
        if chi_sq > 500 and total_bytes > 20:
            score += 10.0

        # Framing error penalty
        if framing_errors > 0:
            score -= min(30.0, framing_errors * 5.0)

        # Fallback: UTF-8/printable check (erd0spy-style)
        printable_ratio = sum(1 for b in raw if 0x20 <= b <= 0x7e or b in (0x0a, 0x0d, 0x09)) / total_bytes
        if printable_ratio > 0.8:
            score += 15.0  # Might be text-based protocol

        sample = packets[0].hex if packets else raw[:16].hex()

        return BaudScanResult(
            baudrate=config.baudrate, bytesize=config.bytesize,
            parity=config.parity, stopbits=config.stopbits,
            score=round(score, 1), entropy=round(entropy, 3),
            packet_count=len(packets),
            consistent_lengths=consistent_lengths,
            consistent_start_byte=consistent_start,
            framing_errors=framing_errors,
            chi_squared=round(chi_sq, 1),
            total_bytes=total_bytes,
            sample_hex=sample[:64],
        )

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _chi_squared(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        expected = len(data) / 256.0
        chi_sq = sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))
        return chi_sq

    @staticmethod
    def _check_consistent_lengths(packets: list[Packet]) -> bool:
        if len(packets) < MIN_PACKETS_FOR_SCORE:
            return False
        lengths = [p.length for p in packets]
        most_common_len, count = Counter(lengths).most_common(1)[0]
        return count / len(lengths) >= 0.5

    @staticmethod
    def _check_consistent_start_byte(packets: list[Packet]) -> bool:
        if len(packets) < MIN_PACKETS_FOR_SCORE:
            return False
        starts = [p.data[0] for p in packets if p.data]
        if not starts:
            return False
        most_common_start, count = Counter(starts).most_common(1)[0]
        return count / len(starts) >= 0.5


# ── Guided Capture ───────────────────────────────────────────────────────────

class GuidedCapture:
    """Phase 3: Interactive step-by-step capture of known actions."""

    GUIDED_STEPS = [
        {"label": "Idle baseline (30s, no interaction)", "module_type": "", "module_index": 0, "channel": 0, "action": "idle", "duration": 30},
        {"label": "MDM8 #1 CH1 ON", "module_type": "MDM8", "module_index": 1, "channel": 1, "action": "on"},
        {"label": "MDM8 #1 CH1 OFF", "module_type": "MDM8", "module_index": 1, "channel": 1, "action": "off"},
        {"label": "MDM8 #1 CH2 ON", "module_type": "MDM8", "module_index": 1, "channel": 2, "action": "on"},
        {"label": "MDM8 #1 CH2 OFF", "module_type": "MDM8", "module_index": 1, "channel": 2, "action": "off"},
        {"label": "MDM8 #1 CH1 DIM ~50%", "module_type": "MDM8", "module_index": 1, "channel": 1, "action": "dim_50"},
        {"label": "MDM8 #1 CH1 DIM ~25%", "module_type": "MDM8", "module_index": 1, "channel": 1, "action": "dim_25"},
        {"label": "MDM8 #1 CH1 DIM ~100%", "module_type": "MDM8", "module_index": 1, "channel": 1, "action": "dim_100"},
        {"label": "MDM8 #2 CH1 ON (module address test)", "module_type": "MDM8", "module_index": 2, "channel": 1, "action": "on"},
        {"label": "MDM8 #2 CH1 OFF", "module_type": "MDM8", "module_index": 2, "channel": 1, "action": "off"},
        {"label": "MDM8 #3 CH1 ON", "module_type": "MDM8", "module_index": 3, "channel": 1, "action": "on"},
        {"label": "MDM8 #3 CH1 OFF", "module_type": "MDM8", "module_index": 3, "channel": 1, "action": "off"},
        {"label": "RDM8-AC Motor 1 OPEN", "module_type": "RDM8-AC", "module_index": 1, "channel": 1, "action": "open"},
        {"label": "RDM8-AC Motor 1 CLOSE", "module_type": "RDM8-AC", "module_index": 1, "channel": 1, "action": "close"},
        {"label": "RDM8-AC Motor 1 STOP", "module_type": "RDM8-AC", "module_index": 1, "channel": 1, "action": "stop"},
        {"label": "RDM8-DC Motor 1 OPEN", "module_type": "RDM8-DC", "module_index": 1, "channel": 1, "action": "open"},
        {"label": "RDM8-DC Motor 1 CLOSE", "module_type": "RDM8-DC", "module_index": 1, "channel": 1, "action": "close"},
        {"label": "RDM8-DC Motor 1 STOP", "module_type": "RDM8-DC", "module_index": 1, "channel": 1, "action": "stop"},
    ]

    def __init__(self, session: CaptureSession, sniffer: SerialSniffer):
        self.session = session
        self.sniffer = sniffer
        self.capture_dir = session.ensure_subdir("phase3_guided")
        self.raw_dir = session.ensure_subdir("phase3_guided", "raw")
        self.captures_file = self.capture_dir / "captures.json"
        self.captures: list[dict] = []
        self._load_existing()

    def _load_existing(self):
        if self.captures_file.exists():
            with open(self.captures_file) as f:
                self.captures = json.load(f)

    def _save(self):
        with open(self.captures_file, "w") as f:
            json.dump(self.captures, f, indent=2)

    @property
    def completed_ids(self) -> set[int]:
        return {c["id"] for c in self.captures}

    def run(self):
        total = len(self.GUIDED_STEPS)
        print(f"\n{'='*60}")
        print("  PHASE 3: GUIDED CAPTURE")
        print(f"  {total} steps — skip any with 's', add notes with 'n', repeat with 'r'")
        print(f"{'='*60}\n")

        for i, step in enumerate(self.GUIDED_STEPS):
            step_id = i + 1
            if step_id in self.completed_ids:
                print(f"  [{step_id}/{total}] {step['label']} — already captured, skipping")
                continue

            result = self._run_step(step_id, total, step)
            if result == "quit":
                print("\n  Session saved. Resume with --resume flag.\n")
                return

        print(f"\n  All {total} guided captures complete!")

    def _run_step(self, step_id: int, total: int, step: dict) -> str:
        while True:
            print(f"\n  Step {step_id}/{total}: {step['label']}")
            if step["action"] == "idle":
                print(f"  → Do NOT touch anything for {step.get('duration', 30)}s.")
            else:
                print(f"  → Prepare to perform: {step['label']}")

            resp = input("  Press ENTER when ready (s=skip, q=quit, n=add note): ").strip().lower()
            if resp == "s":
                print(f"  Skipped step {step_id}.")
                return "skip"
            if resp == "q":
                return "quit"

            notes = ""
            if resp == "n":
                notes = input("  Note: ").strip()

            # Clear sniffer buffer, mark capture start
            self.sniffer.clear()
            t_start = time.perf_counter()
            ts_start = datetime.now().isoformat()

            if step["action"] == "idle":
                duration = step.get("duration", 30)
                print(f"  Capturing idle baseline for {duration}s...")
                for remaining in range(duration, 0, -1):
                    print(f"\r  {remaining}s remaining...  ", end="", flush=True)
                    time.sleep(1)
                print("\r  Done!                    ")
                t_action = t_start  # no specific action moment
                ts_action = ts_start
            else:
                # Pre-action buffer (already capturing in background)
                time.sleep(0.5)
                t_action = time.perf_counter()
                ts_action = datetime.now().isoformat()
                print("  >>> NOW perform the action! Press ENTER when done...")
                input()
                time.sleep(1.0)  # Post-action buffer

            t_end = time.perf_counter()
            ts_end = datetime.now().isoformat()

            packets = self.sniffer.get_packets_since(t_start)

            # Show summary
            print(f"  Captured {len(packets)} packets in {t_end - t_start:.1f}s")
            if packets:
                for j, pkt in enumerate(packets[:10]):
                    print(f"    [{j+1}] len={pkt.length:3d}  {pkt.hex[:48]}{'...' if pkt.length > 24 else ''}")
                if len(packets) > 10:
                    print(f"    ... and {len(packets) - 10} more")

            # Save raw binary
            raw_name = f"{step_id:03d}_{step.get('module_type', 'idle').lower()}-{step.get('module_index', 0)}_ch{step.get('channel', 0)}_{step.get('action', 'idle')}.bin"
            raw_path = self.raw_dir / raw_name
            raw_data = b"".join(p.data for p in packets)
            with open(raw_path, "wb") as f:
                f.write(raw_data)

            entry = CaptureEntry(
                id=step_id,
                label=step["label"],
                module_type=step.get("module_type", ""),
                module_index=step.get("module_index", 0),
                channel=step.get("channel", 0),
                action=step.get("action", ""),
                timestamp_start=ts_start,
                timestamp_action=ts_action,
                timestamp_end=ts_end,
                packets=[p.to_dict() for p in packets],
                raw_file=f"raw/{raw_name}",
                notes=notes,
            )
            self.captures.append(entry.to_dict())
            self._save()

            # Confirm or repeat
            resp2 = input("  Accept? (ENTER=yes, r=repeat): ").strip().lower()
            if resp2 == "r":
                self.captures = [c for c in self.captures if c["id"] != step_id]
                self._save()
                continue
            return "ok"


# ── Test Matrix ──────────────────────────────────────────────────────────────

class TestMatrix:
    """Phase 4: Systematic full-matrix capture across modules/channels."""

    def __init__(self, session: CaptureSession, sniffer: SerialSniffer, modules: list[dict]):
        self.session = session
        self.sniffer = sniffer
        self.modules = modules
        self.capture_dir = session.ensure_subdir("phase4_matrix")
        self.raw_dir = session.ensure_subdir("phase4_matrix", "raw")
        self.captures_file = self.capture_dir / "captures.json"
        self.captures: list[dict] = []
        self._load_existing()

    def _load_existing(self):
        if self.captures_file.exists():
            with open(self.captures_file) as f:
                self.captures = json.load(f)

    def _save(self):
        with open(self.captures_file, "w") as f:
            json.dump(self.captures, f, indent=2)

    @property
    def completed_ids(self) -> set[int]:
        return {c["id"] for c in self.captures}

    def generate_quick_matrix(self) -> list[dict]:
        """2 channels per module (ch1, ch8) × all operations."""
        steps = []
        idx = 0
        for mod in self.modules:
            for ch in [1, min(8, mod["channels"])]:
                for op in mod["operations"]:
                    idx += 1
                    steps.append({
                        "id": idx,
                        "label": f"{mod['label']} CH{ch} {op.upper()}",
                        "module_type": mod["type"],
                        "module_index": mod["index"],
                        "channel": ch,
                        "action": op,
                    })
        return steps

    def generate_full_matrix(self) -> list[dict]:
        """All channels × all operations × all modules."""
        steps = []
        idx = 0
        for mod in self.modules:
            for ch in range(1, mod["channels"] + 1):
                for op in mod["operations"]:
                    idx += 1
                    steps.append({
                        "id": idx,
                        "label": f"{mod['label']} CH{ch} {op.upper()}",
                        "module_type": mod["type"],
                        "module_index": mod["index"],
                        "channel": ch,
                        "action": op,
                    })
        return steps

    def run(self, full: bool = False):
        steps = self.generate_full_matrix() if full else self.generate_quick_matrix()
        total = len(steps)
        mode = "FULL" if full else "QUICK"

        print(f"\n{'='*60}")
        print(f"  PHASE 4: SYSTEMATIC TEST MATRIX ({mode})")
        print(f"  {total} captures — pause with 'p', quit with 'q'")
        print(f"{'='*60}\n")

        for step in steps:
            if step["id"] in self.completed_ids:
                print(f"  [{step['id']}/{total}] {step['label']} — already done")
                continue

            pct = (step["id"] - 1) / total * 100
            bar_len = 30
            filled = int(bar_len * step["id"] / total)
            bar = "=" * filled + ">" + " " * (bar_len - filled - 1)
            print(f"\n  Capture {step['id']}/{total} [{bar}] {pct:.0f}%")
            print(f"  → {step['label']}")

            resp = input("  Press ENTER to capture (s=skip, p=pause, q=quit): ").strip().lower()
            if resp == "q":
                print("\n  Session saved. Resume with --resume flag.")
                return
            if resp == "p":
                print("  Paused. Resume with --resume --phase 4")
                return
            if resp == "s":
                continue

            self.sniffer.clear()
            ts_start = datetime.now().isoformat()
            t_start = time.perf_counter()

            time.sleep(0.5)  # Pre-buffer
            ts_action = datetime.now().isoformat()
            print("  >>> Perform the action NOW! Press ENTER when done...")
            input()
            time.sleep(1.0)  # Post-buffer

            ts_end = datetime.now().isoformat()
            packets = self.sniffer.get_packets_since(t_start)

            print(f"  Got {len(packets)} packets")
            for j, pkt in enumerate(packets[:5]):
                print(f"    [{j+1}] len={pkt.length:3d}  {pkt.hex[:48]}")

            raw_name = f"{step['id']:03d}_{step['module_type'].lower()}-{step['module_index']}_ch{step['channel']}_{step['action']}.bin"
            raw_path = self.raw_dir / raw_name
            raw_data = b"".join(p.data for p in packets)
            with open(raw_path, "wb") as f:
                f.write(raw_data)

            entry = CaptureEntry(
                id=step["id"],
                label=step["label"],
                module_type=step["module_type"],
                module_index=step["module_index"],
                channel=step["channel"],
                action=step["action"],
                timestamp_start=ts_start,
                timestamp_action=ts_action,
                timestamp_end=ts_end,
                packets=[p.to_dict() for p in packets],
                raw_file=f"raw/{raw_name}",
            )
            self.captures.append(entry.to_dict())
            self._save()

        print(f"\n  Matrix complete! {len(self.captures)} captures saved.")


# ── Analyzer ─────────────────────────────────────────────────────────────────

class Analyzer:
    """Post-capture analysis: unique packets, byte-position correlation, checksum testing."""

    def __init__(self, session: CaptureSession):
        self.session = session
        self.analysis_dir = session.ensure_subdir("analysis")

    def run(self):
        print(f"\n{'='*60}")
        print("  ANALYSIS")
        print(f"{'='*60}\n")

        all_captures = []
        for phase_dir in ["phase3_guided", "phase4_matrix"]:
            cap_file = self.session.base_dir / phase_dir / "captures.json"
            if cap_file.exists():
                with open(cap_file) as f:
                    all_captures.extend(json.load(f))

        if not all_captures:
            print("  No captures found to analyze.")
            return

        print(f"  Loaded {len(all_captures)} captures")

        result = {
            "total_captures": len(all_captures),
            "unique_packets": self._unique_packets(all_captures),
            "byte_position_analysis": self._byte_position_analysis(all_captures),
            "idle_traffic": self._idle_traffic(all_captures),
            "checksum_hypotheses": self._checksum_analysis(all_captures),
            "telnet_correlation": self._telnet_correlation(all_captures),
        }

        out_path = self.analysis_dir / "packet_summary.json"
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)

        print(f"  Analysis saved to {out_path}")
        self._print_summary(result)

    def _unique_packets(self, captures: list[dict]) -> list[dict]:
        """Find unique packets with occurrence counts and action contexts."""
        packet_map: dict[str, dict] = {}
        for cap in captures:
            for pkt in cap.get("packets", []):
                hex_str = pkt["hex"]
                if hex_str not in packet_map:
                    packet_map[hex_str] = {
                        "hex": hex_str,
                        "length": pkt["length"],
                        "count": 0,
                        "contexts": [],
                    }
                packet_map[hex_str]["count"] += 1
                ctx = f"{cap.get('label', '?')}"
                if ctx not in packet_map[hex_str]["contexts"]:
                    packet_map[hex_str]["contexts"].append(ctx)

        unique = sorted(packet_map.values(), key=lambda x: x["count"], reverse=True)
        print(f"  Found {len(unique)} unique packets")
        return unique

    def _byte_position_analysis(self, captures: list[dict]) -> dict:
        """For each packet length, analyze each byte position across captures."""
        # Group packets by length
        by_length: dict[int, list[tuple[bytes, dict]]] = {}
        for cap in captures:
            for pkt in cap.get("packets", []):
                pkt_bytes = bytes.fromhex(pkt["hex"])
                length = len(pkt_bytes)
                if length not in by_length:
                    by_length[length] = []
                by_length[length].append((pkt_bytes, cap))

        analysis = {}
        for length, entries in sorted(by_length.items()):
            if len(entries) < 2:
                continue
            positions = []
            for pos in range(length):
                values = [e[0][pos] for e in entries]
                unique_vals = sorted(set(values))
                val_contexts: dict[int, list[str]] = {}
                for pkt_bytes, cap in entries:
                    v = pkt_bytes[pos]
                    if v not in val_contexts:
                        val_contexts[v] = []
                    label = cap.get("label", "?")
                    if label not in val_contexts[v]:
                        val_contexts[v].append(label)

                # Classify position
                if len(unique_vals) == 1:
                    role = "constant"
                elif pos == length - 1:
                    role = "possible_checksum"
                else:
                    # Check correlation with known variables
                    role = self._correlate_position(entries, pos)

                positions.append({
                    "position": pos,
                    "unique_values": [f"0x{v:02x}" for v in unique_vals],
                    "value_count": len(unique_vals),
                    "role": role,
                    "value_contexts": {f"0x{k:02x}": v for k, v in val_contexts.items()},
                })

            analysis[str(length)] = {
                "packet_count": len(entries),
                "positions": positions,
            }

        print(f"  Analyzed byte positions for {len(analysis)} packet lengths")
        return analysis

    def _correlate_position(self, entries: list[tuple[bytes, dict]], pos: int) -> str:
        """Check if byte position correlates with module, channel, or action."""
        # Check module_index correlation
        module_vals: dict[int, set[int]] = {}
        channel_vals: dict[int, set[int]] = {}
        action_vals: dict[str, set[int]] = {}

        for pkt_bytes, cap in entries:
            v = pkt_bytes[pos]
            mi = cap.get("module_index", 0)
            ch = cap.get("channel", 0)
            act = cap.get("action", "")

            if mi:
                module_vals.setdefault(mi, set()).add(v)
            if ch:
                channel_vals.setdefault(ch, set()).add(v)
            if act:
                action_vals.setdefault(act, set()).add(v)

        # If each module_index maps to exactly one byte value
        if module_vals and all(len(vs) == 1 for vs in module_vals.values()):
            if len(set(next(iter(vs)) for vs in module_vals.values())) == len(module_vals):
                return "correlates_module_index"

        if channel_vals and all(len(vs) == 1 for vs in channel_vals.values()):
            if len(set(next(iter(vs)) for vs in channel_vals.values())) == len(channel_vals):
                return "correlates_channel"

        if action_vals and all(len(vs) == 1 for vs in action_vals.values()):
            if len(set(next(iter(vs)) for vs in action_vals.values())) == len(action_vals):
                return "correlates_action"

        return "variable"

    def _idle_traffic(self, captures: list[dict]) -> dict:
        """Analyze idle capture for periodic patterns."""
        idle_caps = [c for c in captures if c.get("action") == "idle"]
        if not idle_caps:
            return {"found": False}

        cap = idle_caps[0]
        packets = cap.get("packets", [])
        if not packets:
            return {"found": True, "packet_count": 0}

        # Check for repeating packets
        hex_list = [p["hex"] for p in packets]
        counter = Counter(hex_list)

        # Check intervals between same packets
        intervals = []
        for pkt in packets[1:]:
            if pkt.get("gap_before_ms") is not None:
                intervals.append(pkt["gap_before_ms"])

        return {
            "found": True,
            "packet_count": len(packets),
            "unique_packets": len(counter),
            "most_common": counter.most_common(5),
            "avg_interval_ms": round(sum(intervals) / len(intervals), 1) if intervals else None,
            "min_interval_ms": round(min(intervals), 1) if intervals else None,
            "max_interval_ms": round(max(intervals), 1) if intervals else None,
        }

    def _checksum_analysis(self, captures: list[dict]) -> list[dict]:
        """Test common checksum algorithms on all packets."""
        results = []
        all_packets = []
        for cap in captures:
            for pkt in cap.get("packets", []):
                if pkt["length"] >= 3:  # Need at least header + data + checksum
                    all_packets.append(bytes.fromhex(pkt["hex"]))

        if not all_packets:
            return results

        # Test: last byte = XOR of all previous bytes
        xor_matches = sum(1 for p in all_packets if self._xor_check(p))
        results.append({
            "algorithm": "XOR (last byte)",
            "matches": xor_matches,
            "total": len(all_packets),
            "ratio": round(xor_matches / len(all_packets), 3),
        })

        # Test: last byte = SUM mod 256 of all previous bytes
        sum_matches = sum(1 for p in all_packets if self._sum_check(p))
        results.append({
            "algorithm": "SUM mod 256 (last byte)",
            "matches": sum_matches,
            "total": len(all_packets),
            "ratio": round(sum_matches / len(all_packets), 3),
        })

        # Test: last byte = 2's complement checksum
        twos_matches = sum(1 for p in all_packets if self._twos_complement_check(p))
        results.append({
            "algorithm": "2's complement sum (last byte)",
            "matches": twos_matches,
            "total": len(all_packets),
            "ratio": round(twos_matches / len(all_packets), 3),
        })

        # Test: CRC-8 (simple polynomial 0x07)
        crc8_matches = sum(1 for p in all_packets if self._crc8_check(p))
        results.append({
            "algorithm": "CRC-8 (poly 0x07, last byte)",
            "matches": crc8_matches,
            "total": len(all_packets),
            "ratio": round(crc8_matches / len(all_packets), 3),
        })

        # Test: last 2 bytes = CRC-16 (Modbus)
        crc16_matches = sum(1 for p in all_packets if len(p) >= 4 and self._crc16_modbus_check(p))
        applicable_crc16 = sum(1 for p in all_packets if len(p) >= 4)
        if applicable_crc16:
            results.append({
                "algorithm": "CRC-16/Modbus (last 2 bytes)",
                "matches": crc16_matches,
                "total": applicable_crc16,
                "ratio": round(crc16_matches / applicable_crc16, 3),
            })

        print(f"  Tested {len(results)} checksum algorithms")
        return results

    @staticmethod
    def _xor_check(data: bytes) -> bool:
        result = 0
        for b in data[:-1]:
            result ^= b
        return result == data[-1]

    @staticmethod
    def _sum_check(data: bytes) -> bool:
        return sum(data[:-1]) % 256 == data[-1]

    @staticmethod
    def _twos_complement_check(data: bytes) -> bool:
        return (256 - sum(data[:-1]) % 256) % 256 == data[-1]

    @staticmethod
    def _crc8_check(data: bytes, poly: int = 0x07) -> bool:
        crc = 0
        for b in data[:-1]:
            crc ^= b
            for _ in range(8):
                if crc & 0x80:
                    crc = (crc << 1) ^ poly
                else:
                    crc <<= 1
                crc &= 0xFF
        return crc == data[-1]

    @staticmethod
    def _crc16_modbus_check(data: bytes) -> bool:
        crc = 0xFFFF
        for b in data[:-2]:
            crc ^= b
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        expected = struct.unpack("<H", data[-2:])[0]
        return crc == expected

    def _telnet_correlation(self, captures: list[dict]) -> dict:
        """
        Cross-reference with known Telnet protocol.
        The Telnet format $DxxZyyL uses module (xx) and zone (yy).
        If bus packets contain bytes that map to the same module/zone scheme,
        we can correlate.
        """
        notes = []
        notes.append("Telnet reference: $DxxZyyL (ON), $DxxZyyD (OFF), $DxxZyyiiTss (DIM)")
        notes.append("State push: *DxxZyyii")
        notes.append("xx = module address (decimal), yy = zone/channel (decimal)")
        notes.append("ii = intensity 00-63 (decimal), ss = transition speed")
        notes.append("")
        notes.append("Look for byte positions that correlate with module_index and channel")
        notes.append("in the byte_position_analysis — those likely correspond to xx and yy.")
        notes.append("A byte that changes between ON/OFF captures likely corresponds to L/D.")
        notes.append("Dim captures should have a byte mapping to intensity (0x00-0x3F = 0-63).")

        return {"notes": notes}

    def _print_summary(self, result: dict):
        print(f"\n  Summary:")
        print(f"  ├─ {result['total_captures']} total captures")
        print(f"  ├─ {len(result['unique_packets'])} unique packets")

        if result["unique_packets"]:
            print(f"  ├─ Top 5 packets by frequency:")
            for p in result["unique_packets"][:5]:
                print(f"  │   {p['hex'][:40]:40s} ×{p['count']} [{', '.join(p['contexts'][:3])}]")

        idle = result["idle_traffic"]
        if idle.get("found") and idle.get("packet_count", 0) > 0:
            print(f"  ├─ Idle traffic: {idle['packet_count']} packets, {idle['unique_packets']} unique")
            if idle.get("avg_interval_ms"):
                print(f"  │   avg interval: {idle['avg_interval_ms']}ms")

        print(f"  ├─ Checksum hypotheses:")
        for ck in result["checksum_hypotheses"]:
            marker = "✓" if ck["ratio"] > 0.8 else "?" if ck["ratio"] > 0.3 else "✗"
            print(f"  │   {marker} {ck['algorithm']}: {ck['matches']}/{ck['total']} ({ck['ratio']*100:.0f}%)")

        bpa = result["byte_position_analysis"]
        if bpa:
            print(f"  └─ Byte-position analysis for {len(bpa)} packet length(s):")
            for length, info in bpa.items():
                print(f"      Length {length} ({info['packet_count']} packets):")
                for pos_info in info["positions"]:
                    if pos_info["role"] != "variable":
                        print(f"        pos[{pos_info['position']}]: {pos_info['role']} "
                              f"({pos_info['value_count']} unique values)")


# ── Wizard Orchestrator ──────────────────────────────────────────────────────

class Wizard:
    """Main orchestrator — walks through all 4 phases."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.session: Optional[CaptureSession] = None
        self.config: Optional[SerialConfig] = None
        self.sniffer: Optional[SerialSniffer] = None
        self.modules: list[dict] = list(DEFAULT_MODULES)

    def run(self):
        self._print_banner()

        if self.args.resume:
            self._resume_session()
        elif self.args.analyze:
            self._analyze_only()
            return
        else:
            self._new_session()

        start_phase = self.args.phase or self._next_phase()

        if start_phase <= 1:
            self._phase1_setup()
        if start_phase <= 2:
            self._phase2_baud()
        if start_phase <= 3:
            self._ensure_sniffer()
            self._phase3_guided()
        if start_phase <= 4:
            self._ensure_sniffer()
            self._phase4_matrix()

        # Run analysis
        self._run_analysis()

        if self.sniffer:
            self.sniffer.stop()

        print(f"\n{'='*60}")
        print(f"  SESSION COMPLETE")
        print(f"  Data saved to: {self.session.base_dir}")
        print(f"{'='*60}\n")

    def _print_banner(self):
        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║     Scenario Classic-NET RS-485 Bus Sniffing Wizard     ║")
        print("║                                                         ║")
        print("║  Reverse-engineer the proprietary Classic-NET protocol  ║")
        print("║  used by Scenario Automacao home automation modules.    ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()

    def _new_session(self):
        base = Path(self.args.session_base) if self.args.session_base else Path(__file__).parent
        self.session = CaptureSession.create(base)
        print(f"  New session: {self.session.base_dir}\n")

    def _resume_session(self):
        session_dir = Path(self.args.resume)
        if not session_dir.exists():
            print(f"  ERROR: Session directory not found: {session_dir}")
            sys.exit(1)
        self.session = CaptureSession.load(session_dir)
        self.modules = self.session.state.get("modules", DEFAULT_MODULES)
        if self.session.state.get("serial_config"):
            sc = self.session.state["serial_config"]
            self.config = SerialConfig(
                port=sc.get("port", ""),
                baudrate=sc.get("baudrate", 9600),
                bytesize=sc.get("bytesize", 8),
                parity=sc.get("parity", "N"),
                stopbits=sc.get("stopbits", 1),
            )
        print(f"  Resumed session: {self.session.base_dir}")
        print(f"  Completed phases: {self.session.state.get('phases_completed', [])}\n")

    def _analyze_only(self):
        session_dir = Path(self.args.analyze)
        if not session_dir.exists():
            print(f"  ERROR: Session directory not found: {session_dir}")
            sys.exit(1)
        session = CaptureSession.load(session_dir)
        analyzer = Analyzer(session)
        analyzer.run()

    def _next_phase(self) -> int:
        completed = self.session.state.get("phases_completed", [])
        if not completed:
            return 1
        return max(completed) + 1

    def _mark_phase_done(self, phase: int):
        completed = self.session.state.setdefault("phases_completed", [])
        if phase not in completed:
            completed.append(phase)
        self.session.save()

    # ── Phase 1: Setup ───────────────────────────────────────────────────

    def _phase1_setup(self):
        print(f"{'='*60}")
        print("  PHASE 1: SETUP")
        print(f"{'='*60}\n")

        # Detect serial port
        port = self._detect_port()
        if not port:
            return

        # Collect module inventory
        self._collect_modules()

        # Save to session
        self.session.state["port"] = port
        self.session.state["modules"] = self.modules
        self._mark_phase_done(1)
        print(f"\n  Phase 1 complete. Port: {port}, {len(self.modules)} modules.\n")

    def _detect_port(self) -> Optional[str]:
        if self.args.port:
            port = self.args.port
            print(f"  Using specified port: {port}")
        else:
            print("  Scanning for USB-to-serial adapters...")
            ports = serial.tools.list_ports.comports()
            usb_ports = [
                p for p in ports
                if "usbserial" in (p.device or "").lower()
                or "usb" in (p.description or "").lower()
                or "ft232" in (p.description or "").lower()
                or "ch340" in (p.description or "").lower()
                or "cp210" in (p.description or "").lower()
                or "ttyUSB" in (p.device or "")
            ]

            if not usb_ports:
                print("\n  No USB serial adapters detected.")
                print("  Available ports:")
                for i, p in enumerate(ports):
                    print(f"    [{i+1}] {p.device} — {p.description}")
                if not ports:
                    print("    (none)")
                    port = input("\n  Enter serial port path manually (or 'q' to quit): ").strip()
                    if port.lower() == "q":
                        return None
                else:
                    choice = input(f"\n  Pick a port [1-{len(ports)}] or enter path manually: ").strip()
                    if choice.isdigit() and 1 <= int(choice) <= len(ports):
                        port = ports[int(choice) - 1].device
                    else:
                        port = choice
            elif len(usb_ports) == 1:
                port = usb_ports[0].device
                print(f"  Found: {port} — {usb_ports[0].description}")
                resp = input(f"  Use this port? (Y/n): ").strip().lower()
                if resp == "n":
                    port = input("  Enter port path: ").strip()
            else:
                print(f"\n  Found {len(usb_ports)} USB serial ports:")
                for i, p in enumerate(usb_ports):
                    print(f"    [{i+1}] {p.device} — {p.description}")
                choice = input(f"\n  Pick [1-{len(usb_ports)}]: ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(usb_ports):
                    port = usb_ports[int(choice) - 1].device
                else:
                    port = choice

        # Validate port
        try:
            test_ser = serial.Serial(port, 9600, timeout=0.1)
            test_ser.close()
            print(f"  Port {port} opened successfully.")
            return port
        except (serial.SerialException, OSError) as e:
            print(f"  ERROR: Cannot open {port}: {e}")
            resp = input("  Continue anyway? (y/N): ").strip().lower()
            if resp == "y":
                return port
            return None

    def _collect_modules(self):
        print(f"\n  Module inventory (pre-filled with your known setup):")
        for i, mod in enumerate(self.modules):
            print(f"    [{i+1}] {mod['label']} ({mod['type']}, {mod['channels']}ch, ops: {', '.join(mod['operations'])})")

        resp = input("\n  Keep this inventory? (Y/n/e=edit): ").strip().lower()
        if resp == "n":
            self.modules = []
            self._add_modules_interactive()
        elif resp == "e":
            self._edit_modules_interactive()

    def _add_modules_interactive(self):
        print("  Add modules (type 'done' when finished):")
        idx = len(self.modules) + 1
        while True:
            mod_type = input(f"  Module {idx} type (MDM8/RDM8-AC/RDM8-DC/done): ").strip()
            if mod_type.lower() == "done":
                break
            channels = input(f"  Number of channels [{8}]: ").strip()
            channels = int(channels) if channels else 8

            if "MDM" in mod_type.upper():
                ops = ["on", "off", "dim"]
            else:
                ops = ["open", "close", "stop"]

            self.modules.append({
                "type": mod_type,
                "index": sum(1 for m in self.modules if m["type"] == mod_type) + 1,
                "label": f"{mod_type} #{sum(1 for m in self.modules if m['type'] == mod_type) + 1}",
                "channels": channels,
                "operations": ops,
            })
            idx += 1

    def _edit_modules_interactive(self):
        while True:
            print("\n  Current modules:")
            for i, mod in enumerate(self.modules):
                print(f"    [{i+1}] {mod['label']}")
            resp = input("  Remove # / add / done: ").strip().lower()
            if resp == "done":
                break
            elif resp == "add":
                self._add_modules_interactive()
            elif resp.isdigit():
                idx = int(resp) - 1
                if 0 <= idx < len(self.modules):
                    removed = self.modules.pop(idx)
                    print(f"  Removed {removed['label']}")

    # ── Phase 2: Baud Detection ──────────────────────────────────────────

    def _phase2_baud(self):
        print(f"\n{'='*60}")
        print("  PHASE 2: BAUD RATE & SERIAL PARAMETER DETECTION")
        print(f"{'='*60}\n")

        port = self.session.state.get("port") or self.args.port
        if not port:
            print("  ERROR: No port configured. Run Phase 1 first.")
            return

        print("  IMPORTANT: During this scan, periodically press buttons on your")
        print("  Scenario keypads to generate bus traffic. The scanner listens for")
        print(f"  {DEFAULT_LISTEN_WINDOW}s per combination.\n")

        input("  Press ENTER to begin primary scan (30 combos, ~90s)...")

        detector = BaudDetector(port, DEFAULT_LISTEN_WINDOW)

        def progress(idx, total, label):
            bar_len = 20
            filled = int(bar_len * idx / total)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"\r  Testing {label:20s} [{bar}] {idx}/{total}", end="", flush=True)

        # Primary scan
        print()
        results = detector.scan(PRIMARY_BAUDS, SERIAL_PARAMS, progress_cb=progress)
        print("\n")

        # Filter results with positive scores
        good_results = [r for r in results if r.score > 0]

        if not good_results:
            print("  No bus traffic detected with primary baud rates.")
            resp = input("  Run extended scan (+60 combos)? (y/N): ").strip().lower()
            if resp == "y":
                print()
                ext_results = detector.scan(EXTENDED_BAUDS, SERIAL_PARAMS, progress_cb=progress)
                print("\n")
                results.extend(ext_results)
                results.sort(key=lambda r: r.score, reverse=True)
                good_results = [r for r in results if r.score > 0]

        if not good_results:
            print("  Still no traffic detected. Possible causes:")
            print("    - Adapter not connected to bus A/B lines")
            print("    - No keypad presses during scan")
            print("    - Baud rate outside scanned range")
            print("    - Bus not powered")

            # Allow manual selection anyway
            resp = input("\n  Enter baud rate manually? (y/N): ").strip().lower()
            if resp == "y":
                baud = int(input("  Baud rate: ").strip())
                params = input("  Params (e.g. 8N1): ").strip()
                bytesize = int(params[0])
                parity = params[1].upper()
                stopbits = int(params[2])
                self.config = SerialConfig(port=port, baudrate=baud, bytesize=bytesize, parity=parity, stopbits=stopbits)
            else:
                return
        else:
            # Show results table
            print("  Scan Results (top 10):")
            print(f"  {'Rank':>4} {'Config':>15} {'Score':>6} {'Pkts':>5} {'Entropy':>8} "
                  f"{'Lengths':>8} {'Start':>6} {'FrmErr':>7} {'Bytes':>6} {'Sample':>24}")
            print(f"  {'─'*4} {'─'*15} {'─'*6} {'─'*5} {'─'*8} {'─'*8} {'─'*6} {'─'*7} {'─'*6} {'─'*24}")

            top = good_results[:10]
            for i, r in enumerate(top):
                print(f"  {i+1:>4} {r.label():>15} {r.score:>6.1f} {r.packet_count:>5} {r.entropy:>8.3f} "
                      f"{'  yes' if r.consistent_lengths else '   no':>8} "
                      f"{'  yes' if r.consistent_start_byte else '   no':>6} "
                      f"{r.framing_errors:>7} {r.total_bytes:>6} {r.sample_hex[:24]:>24}")

            # Let user pick
            if len(top) == 1:
                choice = 1
                print(f"\n  Only one candidate: {top[0].label()}")
            else:
                choice = input(f"\n  Select configuration [1-{len(top)}] (default=1): ").strip()
                choice = int(choice) if choice else 1

            winner = top[choice - 1]
            self.config = SerialConfig(
                port=port,
                baudrate=winner.baudrate,
                bytesize=winner.bytesize,
                parity=winner.parity,
                stopbits=winner.stopbits,
            )

        # Save results
        scan_file = self.session.base_dir / "phase2_baud_scan.json"
        with open(scan_file, "w") as f:
            json.dump({
                "all_results": [r.to_dict() for r in results],
                "selected": {
                    "baudrate": self.config.baudrate,
                    "bytesize": self.config.bytesize,
                    "parity": self.config.parity,
                    "stopbits": self.config.stopbits,
                },
            }, f, indent=2)

        self.session.state["serial_config"] = {
            "port": self.config.port,
            "baudrate": self.config.baudrate,
            "bytesize": self.config.bytesize,
            "parity": self.config.parity,
            "stopbits": self.config.stopbits,
        }
        self._mark_phase_done(2)

        print(f"\n  Selected: {self.config.label()}")
        print(f"  Byte time: {self.config.byte_time()*1000:.3f}ms")
        print(f"  Gap threshold: {self.config.byte_time() * GAP_MULTIPLIER * 1000:.3f}ms")
        print(f"  Phase 2 complete.\n")

    # ── Phase 3: Guided Capture ──────────────────────────────────────────

    def _phase3_guided(self):
        guided = GuidedCapture(self.session, self.sniffer)
        guided.run()
        self._mark_phase_done(3)

        # Run analysis after guided capture
        analyzer = Analyzer(self.session)
        analyzer.run()

    # ── Phase 4: Test Matrix ─────────────────────────────────────────────

    def _phase4_matrix(self):
        print(f"\n  Choose matrix size:")
        print(f"    [q] Quick — 2 channels per module (ch1, ch8) × all ops")
        print(f"    [f] Full  — All 8 channels × all ops × all modules")
        print(f"    [s] Skip Phase 4")

        resp = input("\n  Choice [q/f/s]: ").strip().lower()
        if resp == "s":
            return

        full = resp == "f"
        matrix = TestMatrix(self.session, self.sniffer, self.modules)
        matrix.run(full=full)
        self._mark_phase_done(4)

    # ── Sniffer management ───────────────────────────────────────────────

    def _ensure_sniffer(self):
        if self.sniffer:
            return

        if not self.config:
            sc = self.session.state.get("serial_config", {})
            if not sc:
                print("  ERROR: No serial config. Run Phase 2 first.")
                sys.exit(1)
            self.config = SerialConfig(
                port=sc["port"],
                baudrate=sc["baudrate"],
                bytesize=sc["bytesize"],
                parity=sc["parity"],
                stopbits=sc["stopbits"],
            )

        print(f"  Starting sniffer: {self.config.label()} on {self.config.port}")
        self.sniffer = SerialSniffer(self.config)
        try:
            self.sniffer.start()
            print("  Sniffer running (background thread).\n")
        except serial.SerialException as e:
            print(f"  ERROR: Cannot open serial port: {e}")
            sys.exit(1)

    # ── Analysis ─────────────────────────────────────────────────────────

    def _run_analysis(self):
        analyzer = Analyzer(self.session)
        analyzer.run()


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scenario Classic-NET RS-485 Bus Sniffing Wizard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sniff_classicnet.py                           # full wizard
  python3 sniff_classicnet.py --resume sessions/2026-03-16_143022/
  python3 sniff_classicnet.py --phase 3 --resume sessions/2026-03-16_143022/
  python3 sniff_classicnet.py --analyze sessions/2026-03-16_143022/
  python3 sniff_classicnet.py --port /dev/cu.usbserial-XYZ
        """,
    )
    parser.add_argument("--resume", metavar="SESSION_DIR",
                        help="Resume an existing session")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4],
                        help="Jump to a specific phase")
    parser.add_argument("--analyze", metavar="SESSION_DIR",
                        help="Re-run analysis only on existing session")
    parser.add_argument("--port", metavar="PORT",
                        help="Serial port path (skip auto-detection)")
    parser.add_argument("--session-base", metavar="DIR",
                        help="Base directory for sessions (default: script directory)")

    args = parser.parse_args()

    wizard = Wizard(args)
    try:
        wizard.run()
    except KeyboardInterrupt:
        print("\n\n  Interrupted. Session data has been saved.")
        if wizard.sniffer:
            wizard.sniffer.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()

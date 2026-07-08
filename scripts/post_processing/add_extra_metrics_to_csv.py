#!/usr/bin/env python3
"""
Fast PCAP Preprocessor for DNS QoS Analysis.

Loads PCAP into memory, then uses binary search to match packets to query
windows. Direction is determined by a configured local IP (the netns veth IP).
"""

import argparse
import bisect
import csv
import shutil
import socket
import time
from pathlib import Path
from typing import Dict, List, NamedTuple

import dpkt
from dateutil import parser as date_parser

BANDWIDTH_COLUMNS = [
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
    "total_bytes",
]

DEFAULT_LOCAL_IP = "192.168.100.2"  # netns veth1 address
DEFAULT_PROVIDERS = ["adguard", "cloudflare", "google", "quad9"]


class Packet(NamedTuple):
    timestamp: float
    size: int
    is_outbound: bool


def needs_processing(csv_path: Path) -> bool:
    """True if file lacks bandwidth columns OR all values are empty/zero."""
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return True
            if not all(c in reader.fieldnames for c in BANDWIDTH_COLUMNS):
                return True
            for row in reader:
                for col in BANDWIDTH_COLUMNS:
                    val = (row.get(col) or "").strip()
                    if val and val != "0":
                        return False  # has real data
            return True  # columns exist but all empty/zero
    except Exception:
        return True


def parse_csv_timestamp(ts_str: str) -> float:
    return date_parser.isoparse(ts_str).timestamp()


def load_pcap(pcap_path: Path, local_ip_bytes: bytes) -> List[Packet]:
    """Load PCAP into a list of Packets sorted by timestamp."""
    print("    Loading PCAP...")
    t0 = time.time()
    packets: List[Packet] = []

    with open(pcap_path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                if ip.src == local_ip_bytes:
                    is_outbound = True
                elif ip.dst == local_ip_bytes:
                    is_outbound = False
                else:
                    continue  # not our traffic
                packets.append(Packet(float(ts), len(buf), is_outbound))
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, AttributeError):
                continue

    packets.sort(key=lambda p: p.timestamp)
    print(f"    Loaded {len(packets):,} packets in {time.time() - t0:.2f}s")
    return packets


def load_csv_queries(csv_path: Path) -> List[Dict]:
    queries = []
    with open(csv_path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                start = parse_csv_timestamp(row["timestamp"])
                duration = float(row["duration_ns"]) / 1e9
                queries.append(
                    {"data": row, "start_time": start, "end_time": start + duration}
                )
            except Exception as e:
                print(f"    Warning: skipping row - {e}")
    return queries


def match_packets(packets: List[Packet], queries: List[Dict]) -> int:
    """Assign bandwidth metrics to each query. Returns total matched packets."""
    if not packets or not queries:
        for q in queries:
            q.update({c: 0 for c in BANDWIDTH_COLUMNS})
        return 0

    print("    Matching packets to queries...")
    t0 = time.time()
    timestamps = [p.timestamp for p in packets]
    matched = 0

    for q in queries:
        lo = bisect.bisect_left(timestamps, q["start_time"])
        hi = bisect.bisect_right(timestamps, q["end_time"])
        bs = br = ps = pr = 0
        for pkt in packets[lo:hi]:
            if pkt.is_outbound:
                bs += pkt.size
                ps += 1
            else:
                br += pkt.size
                pr += 1
        q["bytes_sent"] = bs
        q["bytes_received"] = br
        q["packets_sent"] = ps
        q["packets_received"] = pr
        q["total_bytes"] = bs + br
        matched += ps + pr

    print(f"    Matched {matched:,} packets in {time.time() - t0:.2f}s")
    total_sent = sum(q["bytes_sent"] for q in queries)
    total_recv = sum(q["bytes_received"] for q in queries)
    with_data = sum(1 for q in queries if q["total_bytes"] > 0)
    print(f"    Total: {total_sent:,} B sent, {total_recv:,} B received")
    print(f"    Queries with data: {with_data}/{len(queries)}")
    return matched


def write_csv(csv_path: Path, queries: List[Dict], backup: bool = True):
    if backup and csv_path.exists():
        bak = csv_path.with_suffix(".csv.bak")
        if not bak.exists():
            shutil.copy2(csv_path, bak)
            print(f"    Backup: {bak.name}")

    original_fields = [
        f for f in queries[0]["data"].keys() if f not in BANDWIDTH_COLUMNS
    ]
    fieldnames = original_fields + BANDWIDTH_COLUMNS

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for q in queries:
            row = {k: q["data"][k] for k in original_fields}
            for c in BANDWIDTH_COLUMNS:
                row[c] = q[c]
            writer.writerow(row)
    print(f"    Written: {csv_path.name}")


def process_provider(provider_path: Path, local_ip_bytes: bytes):
    print(f"\n{'=' * 60}\nProcessing: {provider_path.name.upper()}\n{'=' * 60}")

    processed = skipped = 0
    total_time = 0.0

    for csv_path in sorted(provider_path.glob("*.csv")):
        name = csv_path.name.lower()
        if ".bak" in name or name.endswith((".cpu.csv", ".mem.csv")):
            continue

        pcap_path = csv_path.with_suffix(".pcap")
        if not pcap_path.exists():
            print(f"\n  ⚠ {csv_path.name}: no matching PCAP")
            continue

        if not needs_processing(csv_path):
            print(f"\n  ⏭ {csv_path.name}: already processed")
            skipped += 1
            continue

        print(f"\n  📁 {csv_path.name}")
        t0 = time.time()

        packets = load_pcap(pcap_path, local_ip_bytes)
        if not packets:
            print("    ⚠ No usable packets in PCAP")
            continue

        queries = load_csv_queries(csv_path)
        if not queries:
            print("    ⚠ No valid queries in CSV")
            continue
        print(f"    Loaded {len(queries):,} queries")

        match_packets(packets, queries)
        write_csv(csv_path, queries)

        dt = time.time() - t0
        total_time += dt
        processed += 1
        print(f"    ✓ Completed in {dt:.2f}s")

    print(
        f"\n  {provider_path.name}: {processed} processed, "
        f"{skipped} skipped, {total_time:.2f}s"
    )

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--local-ip",
        default=DEFAULT_LOCAL_IP,
        help=f"Local (netns veth) IP used to determine direction "
        f"(default: {DEFAULT_LOCAL_IP})",
    )
    ap.add_argument("--results-dir", default="results", type=Path)
    ap.add_argument("--providers", nargs="+", default=DEFAULT_PROVIDERS)
    args = ap.parse_args()

    local_ip_bytes = socket.inet_aton(args.local_ip)

    print(f"\n{'=' * 60}\nDNS PCAP PREPROCESSOR\n{'=' * 60}")
    print(f"Local IP: {args.local_ip}")
    print(f"Results:  {args.results_dir}")

    if not args.results_dir.exists():
        print(f"\n❌ Directory not found: {args.results_dir}")
        return

    t0 = time.time()
    for provider in args.providers:
        path = args.results_dir / provider
        if path.exists():
            process_provider(path, local_ip_bytes)
        else:
            print(f"\n⚠ Missing provider directory: {provider}")

    total = time.time() - t0
    print(f"\n{'=' * 60}")
    print(f"✓ DONE in {total:.2f}s ({total / 60:.1f} min)")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()

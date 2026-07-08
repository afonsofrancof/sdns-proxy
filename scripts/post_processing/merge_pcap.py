#!/usr/bin/env python3
"""
Summarize all .pcap files into a single unified PCAP metrics CSV.
Each row represents one scenario (one PCAP file): total bytes/packets sent and received.
Adds provider, protocol, dnssec_mode, keep_alive columns parsed from filenames.
"""

import argparse
import socket
import time
import csv
from pathlib import Path
from typing import List, NamedTuple

import dpkt


DEFAULT_LOCAL_IP = "192.168.100.2"  # netns veth1 address
DEFAULT_PROVIDERS = ["adguard", "cloudflare", "google", "quad9"]


class PacketSummary(NamedTuple):
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    total_bytes: int
    total_packets: int


def parse_config_from_filename(filename: str) -> dict:
    """Parse protocol, dnssec_mode, keep_alive from filename like 'dot-trust-persist.pcap'"""
    base = filename.replace(".pcap", "").replace(".PCAP", "")
    parts = base.split("-")

    protocol = parts[0]
    dnssec_mode = "off"
    keep_alive = 0

    for part in parts[1:]:
        if part in ("auth", "trust"):
            dnssec_mode = part
        elif part == "persist":
            keep_alive = 1

    return {
        "protocol": protocol,
        "dnssec_mode": dnssec_mode,
        "keep_alive": keep_alive,
    }


def find_pcap_files(input_dir: Path, providers: List[str]) -> List[Path]:
    files: List[Path] = []
    for provider in providers:
        provider_path = input_dir / provider
        if not provider_path.exists():
            print(f"  ⚠ Missing provider directory: {provider}")
            continue
        for p in sorted(provider_path.glob("*.pcap")):
            if ".bak" not in p.name:
                files.append(p)
    return files


def summarize_pcap(pcap_path: Path, local_ip_bytes: bytes) -> PacketSummary:
    """Read a PCAP file and return aggregated byte/packet counts by direction."""
    bytes_sent = bytes_received = packets_sent = packets_received = 0

    with open(pcap_path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for _ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                size = len(buf)
                if ip.src == local_ip_bytes:
                    bytes_sent += size
                    packets_sent += 1
                elif ip.dst == local_ip_bytes:
                    bytes_received += size
                    packets_received += 1
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, AttributeError):
                continue

    return PacketSummary(
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        packets_sent=packets_sent,
        packets_received=packets_received,
        total_bytes=bytes_sent + bytes_received,
        total_packets=packets_sent + packets_received,
    )


def merge_pcap_files(input_dir: Path, output_path: Path, local_ip: str, providers: List[str]):
    local_ip_bytes = socket.inet_aton(local_ip)

    pcap_files = find_pcap_files(input_dir, providers)
    if not pcap_files:
        print("No .pcap files found.")
        return

    print(f"Found {len(pcap_files)} PCAP files")
    print(f"Local IP: {local_ip}\n")

    output_columns = [
        "id", "provider", "protocol", "dnssec_mode", "keep_alive",
        "bytes_sent", "bytes_received", "packets_sent", "packets_received",
        "total_bytes", "total_packets",
    ]

    total_rows = 0
    t_total = time.time()

    with open(output_path, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=output_columns)
        writer.writeheader()

        for pcap_path in pcap_files:
            provider = pcap_path.parent.name.lower()
            config = parse_config_from_filename(pcap_path.name)

            print(f"  {provider}/{pcap_path.name} "
                  f"({config['protocol']}, {config['dnssec_mode']}, persist={config['keep_alive']})")

            t0 = time.time()
            summary = summarize_pcap(pcap_path, local_ip_bytes)
            dt = time.time() - t0

            total_rows += 1
            writer.writerow({
                "id": total_rows,
                "provider": provider,
                "protocol": config["protocol"],
                "dnssec_mode": config["dnssec_mode"],
                "keep_alive": config["keep_alive"],
                "bytes_sent": summary.bytes_sent,
                "bytes_received": summary.bytes_received,
                "packets_sent": summary.packets_sent,
                "packets_received": summary.packets_received,
                "total_bytes": summary.total_bytes,
                "total_packets": summary.total_packets,
            })

            print(f"    ✓ {summary.packets_sent:,} sent / {summary.packets_received:,} received "
                  f"| {summary.total_bytes:,} B total  ({dt:.2f}s)")

    elapsed = time.time() - t_total
    print(f"\n{'=' * 60}")
    print(f"PCAP metrics merged → {output_path}")
    print(f"Total scenarios: {total_rows}")
    print(f"Completed in {elapsed:.2f}s ({elapsed / 60:.1f} min)")
    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(description="Summarize all .pcap files into a unified CSV.")
    parser.add_argument("input_dir", nargs="?", default=".", help="Input directory (default: .)")
    parser.add_argument("-o", "--output", default="dns_results_pcap.csv", help="Output CSV path")
    parser.add_argument("--local-ip", default=DEFAULT_LOCAL_IP,
                        help=f"Local netns veth IP for direction detection (default: {DEFAULT_LOCAL_IP})")
    parser.add_argument("--providers", nargs="+", default=DEFAULT_PROVIDERS,
                        help="Provider subdirectory names to scan")
    args = parser.parse_args()

    merge_pcap_files(Path(args.input_dir), Path(args.output), args.local_ip, args.providers)
    return 0


if __name__ == "__main__":
    exit(main())

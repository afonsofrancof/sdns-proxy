#!/usr/bin/env python3
"""
Fast PCAP Preprocessor for DNS QoS Analysis
Loads PCAP into memory first, then uses binary search for matching.
Uses LAN IP to determine direction (LAN = sent, non-LAN = received).
"""

import csv
import shutil
from pathlib import Path
from typing import Dict, List, NamedTuple
import time

import dpkt
from dateutil import parser as date_parser


class Packet(NamedTuple):
    """Lightweight packet representation."""
    timestamp: float
    size: int
    is_outbound: bool  # True if from LAN, False if from internet


class QueryWindow:
    """Efficient query window representation."""
    __slots__ = ['index', 'start', 'end', 'sent', 'received', 'pkts_sent', 'pkts_received']
    
    def __init__(self, index: int, start: float, end: float):
        self.index = index
        self.start = start
        self.end = end
        self.sent = 0
        self.received = 0
        self.pkts_sent = 0
        self.pkts_received = 0


def parse_csv_timestamp(ts_str: str) -> float:
    """Convert RFC3339Nano timestamp to Unix epoch (seconds)."""
    dt = date_parser.isoparse(ts_str)
    return dt.timestamp()


def is_lan_ip(ip_bytes: bytes) -> bool:
    """Check if IP is a private/LAN address."""
    if len(ip_bytes) != 4:
        return False
    
    first = ip_bytes[0]
    second = ip_bytes[1]
    
    # 10.0.0.0/8
    if first == 10:
        return True
    
    # 172.16.0.0/12
    if first == 172 and 16 <= second <= 31:
        return True
    
    # 192.168.0.0/16
    if first == 192 and second == 168:
        return True
    
    # 127.0.0.0/8 (localhost)
    if first == 127:
        return True
    
    return False


def load_pcap_into_memory(pcap_path: Path) -> List[Packet]:
    """Load all packets from PCAP into memory with minimal data."""
    packets = []
    
    print(f"    Loading PCAP into memory...")
    start_time = time.time()
    
    try:
        with open(pcap_path, 'rb') as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except:
                # Try pcapng format
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)
            
            for ts, buf in pcap:
                try:
                    packet_time = float(ts)
                    packet_size = len(buf)
                    
                    # Parse to get source IP
                    eth = dpkt.ethernet.Ethernet(buf)
                    
                    # Default to outbound if we can't determine
                    is_outbound = True
                    
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src_ip = ip.src
                        is_outbound = is_lan_ip(src_ip)
                    
                    packets.append(Packet(
                        timestamp=packet_time,
                        size=packet_size,
                        is_outbound=is_outbound
                    ))
                    
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, AttributeError):
                    continue
    
    except Exception as e:
        print(f"    Error reading PCAP: {e}")
        return []
    
    elapsed = time.time() - start_time
    print(f"    Loaded {len(packets):,} packets in {elapsed:.2f}s")
    
    # Sort by timestamp for binary search
    packets.sort(key=lambda p: p.timestamp)
    
    return packets


def find_packets_in_window(
    packets: List[Packet],
    start_time: float,
    end_time: float,
    left_hint: int = 0
) -> tuple[List[Packet], int]:
    """
    Binary search to find all packets within time window.
    Returns (matching_packets, left_index_hint_for_next_search).
    """
    if not packets:
        return [], 0
    
    # Binary search for first packet >= start_time
    left, right = left_hint, len(packets) - 1
    first_idx = len(packets)
    
    while left <= right:
        mid = (left + right) // 2
        if packets[mid].timestamp >= start_time:
            first_idx = mid
            right = mid - 1
        else:
            left = mid + 1
    
    # No packets in range
    if first_idx >= len(packets) or packets[first_idx].timestamp > end_time:
        return [], first_idx
    
    # Collect all packets in window
    matching = []
    idx = first_idx
    while idx < len(packets) and packets[idx].timestamp <= end_time:
        matching.append(packets[idx])
        idx += 1
    
    return matching, first_idx


def load_csv_queries(csv_path: Path) -> List[Dict]:
    """Load CSV and create query data structures."""
    queries = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts_epoch = parse_csv_timestamp(row['timestamp'])
                duration_s = float(row['duration_ns']) / 1e9
                queries.append({
                    'data': row,
                    'start_time': ts_epoch,
                    'end_time': ts_epoch + duration_s,
                })
            except Exception as e:
                print(f"  Warning: Skipping row - {e}")
                continue
    return queries


def match_packets_to_queries(
    packets: List[Packet],
    queries: List[Dict]
) -> List[Dict]:
    """Match packets to query windows using binary search."""
    if not queries or not packets:
        return queries
    
    print(f"    Matching packets to queries...")
    start_time = time.time()
    
    # Initialize metrics
    for q in queries:
        q['bytes_sent'] = 0
        q['bytes_received'] = 0
        q['packets_sent'] = 0
        q['packets_received'] = 0
        q['total_bytes'] = 0
    
    # Sort queries by start time for sequential processing
    queries_sorted = sorted(enumerate(queries), key=lambda x: x[1]['start_time'])
    
    matched_packets = 0
    left_hint = 0  # Optimization: start next search from here
    
    for original_idx, q in queries_sorted:
        matching, left_hint = find_packets_in_window(
            packets,
            q['start_time'],
            q['end_time'],
            left_hint
        )
        
        for pkt in matching:
            matched_packets += 1
            if pkt.is_outbound:
                q['bytes_sent'] += pkt.size
                q['packets_sent'] += 1
            else:
                q['bytes_received'] += pkt.size
                q['packets_received'] += 1
        
        q['total_bytes'] = q['bytes_sent'] + q['bytes_received']
    
    elapsed = time.time() - start_time
    print(f"    Matched {matched_packets:,} packets in {elapsed:.2f}s")
    
    # Statistics
    total_sent = sum(q['bytes_sent'] for q in queries)
    total_recv = sum(q['bytes_received'] for q in queries)
    queries_with_data = sum(1 for q in queries if q['total_bytes'] > 0)
    print(f"    Total: {total_sent:,} bytes sent, {total_recv:,} bytes received")
    print(f"    Queries with data: {queries_with_data}/{len(queries)}")
    
    return queries


def write_enriched_csv(
    csv_path: Path, queries: List[Dict], backup: bool = True
):
    """Write enriched CSV with bandwidth columns."""
    if backup and csv_path.exists():
        backup_path = csv_path.with_suffix('.csv.bak')
        if not backup_path.exists():  # Don't overwrite existing backup
            shutil.copy2(csv_path, backup_path)
            print(f"  Backup: {backup_path.name}")
    
    # Get fieldnames
    original_fields = list(queries[0]['data'].keys())
    new_fields = [
        'bytes_sent',
        'bytes_received',
        'packets_sent',
        'packets_received',
        'total_bytes',
    ]
    fieldnames = original_fields + new_fields
    
    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for q in queries:
            row = q['data'].copy()
            for field in new_fields:
                row[field] = q[field]
            writer.writerow(row)
    
    print(f"  Written: {csv_path.name}")


def process_provider_directory(provider_path: Path):
    """Process all CSV/PCAP pairs in a provider directory."""
    print(f"\n{'='*60}")
    print(f"Processing: {provider_path.name.upper()}")
    print(f"{'='*60}")
    
    csv_files = sorted(provider_path.glob('*.csv'))
    processed = 0
    total_time = 0
    
    for csv_path in csv_files:
        # Skip backup files
        if '.bak' in csv_path.name:
            continue
        
        pcap_path = csv_path.with_suffix('.pcap')
        
        if not pcap_path.exists():
            print(f"\n  ⚠ Skipping {csv_path.name} - no matching PCAP")
            continue
        
        print(f"\n  📁 {csv_path.name}")
        file_start = time.time()
        
        # Load PCAP into memory first
        packets = load_pcap_into_memory(pcap_path)
        if not packets:
            print(f"    ⚠ No packets found in PCAP")
            continue
        
        # Load CSV queries
        queries = load_csv_queries(csv_path)
        if not queries:
            print(f"    ⚠ No valid queries found")
            continue
        
        print(f"    Loaded {len(queries):,} queries")
        
        # Match packets to queries
        enriched_queries = match_packets_to_queries(packets, queries)
        
        # Write enriched CSV
        write_enriched_csv(csv_path, enriched_queries)
        
        file_time = time.time() - file_start
        total_time += file_time
        processed += 1
        print(f"    ✓ Completed in {file_time:.2f}s")
    
    print(f"\n  {'='*58}")
    print(f"  {provider_path.name}: {processed} files in {total_time:.2f}s")
    print(f"  {'='*58}")


def main():
    """Main preprocessing pipeline."""
    overall_start = time.time()
    
    print("\n" + "="*60)
    print("DNS PCAP PREPROCESSOR - Memory-Optimized Edition")
    print("="*60)
    
    results_dir = Path('results')
    
    if not results_dir.exists():
        print(f"\n❌ Error: '{results_dir}' directory not found")
        return
    
    providers = ['adguard', 'cloudflare', 'google', 'quad9']
    
    for provider in providers:
        provider_path = results_dir / provider
        if provider_path.exists():
            process_provider_directory(provider_path)
        else:
            print(f"\n⚠ Warning: Provider directory not found: {provider}")
    
    overall_time = time.time() - overall_start
    
    print("\n" + "="*60)
    print(f"✓ PREPROCESSING COMPLETE")
    print(f"  Total time: {overall_time:.2f}s ({overall_time/60:.1f} minutes)")
    print("="*60 + "\n")


if __name__ == '__main__':
    main()

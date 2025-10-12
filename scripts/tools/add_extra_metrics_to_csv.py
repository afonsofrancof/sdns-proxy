#!/usr/bin/env python3
"""
Add network metrics from PCAP files to DNS CSV files.
Adds: raw_bytes_total, raw_packet_count, overhead_bytes, efficiency_percent
"""

import csv
import os
import argparse
import re
from pathlib import Path
from datetime import datetime, timezone
from scapy.all import rdpcap

def parse_timestamp(ts_str):
    """Parse timestamp with timezone and nanoseconds (RFC3339Nano)."""
    match = re.match(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)([\+\-]\d{2}:\d{2})',
        ts_str
    )
    
    if not match:
        raise ValueError(f"Invalid timestamp format: {ts_str}")
    
    base, nanos, tz = match.groups()
    micros = nanos[:6].ljust(6, '0')
    iso_str = f"{base}.{micros}{tz}"
    dt = datetime.fromisoformat(iso_str)
    full_nanos = int(nanos.ljust(9, '0'))
    
    return dt, full_nanos

def read_pcap(pcap_path):
    """Read PCAP and return list of (timestamp_epoch, size)."""
    packets = []
    try:
        pkts = rdpcap(str(pcap_path))
        for pkt in pkts:
            timestamp = float(pkt.time)
            length = len(pkt)
            packets.append((timestamp, length))
    except Exception as e:
        print(f"  ❌ Error reading PCAP: {e}")
        return []
    
    return packets

def find_packets_in_window(packets, start_ts, start_nanos, duration_ns):
    """Find packets within exact time window."""
    start_epoch = start_ts.timestamp()
    start_epoch += (start_nanos % 1_000_000) / 1_000_000_000
    end_epoch = start_epoch + (duration_ns / 1_000_000_000)
    
    total_bytes = 0
    packet_count = 0
    
    for pkt_ts, pkt_len in packets:
        if start_epoch <= pkt_ts <= end_epoch:
            total_bytes += pkt_len
            packet_count += 1
    
    return total_bytes, packet_count

def enhance_csv(csv_path, pcap_path, output_path, debug=False):
    """Add PCAP metrics to CSV."""
    if not os.path.exists(pcap_path):
        print(f"⚠️  PCAP not found: {pcap_path}")
        return False
    
    print(f"Processing: {os.path.basename(csv_path)}")
    
    # Read PCAP
    packets = read_pcap(pcap_path)
    print(f"  Loaded {len(packets)} packets")
    
    if not packets:
        print("  ❌ No packets found")
        return False
    
    if packets and debug:
        first_pcap = packets[0][0]
        last_pcap = packets[-1][0]
        print(f"  First PCAP packet: {first_pcap:.6f}")
        print(f"  Last PCAP packet:  {last_pcap:.6f}")
        print(f"  PCAP duration: {(last_pcap - first_pcap):.3f}s")
    
    # Read CSV
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) + [
            'raw_bytes_total',
            'raw_packet_count',
            'overhead_bytes',
            'efficiency_percent'
        ]
        rows = list(reader)
    
    if rows and debug:
        try:
            first_ts, _ = parse_timestamp(rows[0]['timestamp'])
            last_ts, _ = parse_timestamp(rows[-1]['timestamp'])
            print(f"  First CSV query:  {first_ts.timestamp():.6f}")
            print(f"  Last CSV query:   {last_ts.timestamp():.6f}")
            offset = packets[0][0] - first_ts.timestamp()
            print(f"  Time offset (PCAP - CSV): {offset:.3f}s")
        except:
            pass
    
    # Enhance rows
    enhanced = []
    matched = 0
    
    for i, row in enumerate(rows):
        try:
            timestamp, nanos = parse_timestamp(row['timestamp'])
            duration_ns = int(row['duration_ns'])
            
            raw_bytes, packet_count = find_packets_in_window(
                packets, timestamp, nanos, duration_ns
            )
            
            useful_bytes = (
                int(row['request_size_bytes']) + 
                int(row['response_size_bytes'])
            )
            overhead = raw_bytes - useful_bytes
            efficiency = (
                (useful_bytes / raw_bytes * 100) 
                if raw_bytes > 0 else 0
            )
            
            row['raw_bytes_total'] = raw_bytes
            row['raw_packet_count'] = packet_count
            row['overhead_bytes'] = overhead
            row['efficiency_percent'] = f"{efficiency:.2f}"
            
            if raw_bytes > 0:
                matched += 1
            
            # Debug first few queries
            if debug and i < 3:
                print(f"  Query {i}: {row['domain']}")
                print(f"    Duration: {duration_ns / 1e6:.3f}ms")
                print(f"    Matched packets: {packet_count}")
                print(f"    Raw bytes: {raw_bytes}")
                print(f"    Useful bytes: {useful_bytes}")
                print(f"    Efficiency: {efficiency:.2f}%")
            
        except (ValueError, KeyError) as e:
            if debug:
                print(f"  Error processing row {i}: {e}")
            row['raw_bytes_total'] = 0
            row['raw_packet_count'] = 0
            row['overhead_bytes'] = 0
            row['efficiency_percent'] = "0.00"
        
        enhanced.append(row)
    
    print(f"  Matched: {matched}/{len(rows)} queries")
    
    if matched == 0:
        print("  ⚠️  WARNING: No queries matched any packets!")
        print("     This might indicate timestamp misalignment.")
    
    # Write output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(enhanced)
    
    print(f"  ✓ Saved: {output_path}")
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Add PCAP network metrics to DNS CSV files'
    )
    parser.add_argument('input_dir', help='Input directory (e.g., results)')
    parser.add_argument(
        '--output',
        default='./results_enriched',
        help='Output directory (default: ./results_enriched)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview files without processing'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Show detailed timing information'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("ENHANCE DNS CSVs WITH PCAP METRICS")
    print("=" * 60)
    print(f"Input:  {args.input_dir}")
    print(f"Output: {args.output}")
    if args.debug:
        print("Debug:  ENABLED")
    print()
    
    # Find CSV files
    csv_files = list(Path(args.input_dir).rglob('*.csv'))
    
    if not csv_files:
        print("❌ No CSV files found")
        return 1
    
    print(f"Found {len(csv_files)} CSV files\n")
    
    if args.dry_run:
        print("DRY RUN - would process:")
        for csv_path in csv_files:
            pcap_path = csv_path.with_suffix('.pcap')
            print(f"  {csv_path.relative_to(args.input_dir)}")
            print(f"    PCAP: {'✓' if pcap_path.exists() else '✗'}")
        return 0
    
    # Process files
    success = 0
    failed = 0
    
    for csv_path in csv_files:
        pcap_path = csv_path.with_suffix('.pcap')
        rel_path = csv_path.relative_to(args.input_dir)
        output_path = Path(args.output) / rel_path
        
        if enhance_csv(str(csv_path), str(pcap_path), str(output_path), 
                       args.debug):
            success += 1
        else:
            failed += 1
        print()
    
    # Summary
    print("=" * 60)
    print(f"✓ Success: {success}")
    print(f"✗ Failed:  {failed}")
    print(f"Total:     {len(csv_files)}")
    print(f"\nOutput: {args.output}")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    exit(main())

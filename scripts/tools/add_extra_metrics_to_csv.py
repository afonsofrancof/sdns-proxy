#!/usr/bin/env python3
"""
Add network metrics from PCAP files to DNS CSV files.
Adds: pcap_network_bytes_in, pcap_network_bytes_out, pcap_overhead_bytes
"""

import csv
import os
import argparse
from pathlib import Path
from datetime import datetime, timezone
import dpkt
import socket

# Test machine IPs
TEST_IPS = {
    '10.0.0.50',
    '2001:818:e73e:ba00:5506:dfd4:ed8b:96e',
    'fe80::fe98:c62e:4463:9a2d'
}


def inet_to_str(inet):
    """Convert inet bytes to IP string"""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return None


def read_pcap(pcap_path):
    """Read PCAP and return list of (timestamp_ns, size, src_ip, dst_ip)"""
    packets = []
    
    with open(pcap_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)
        
        for ts, buf in pcap:
            try:
                # Convert PCAP timestamp (float seconds) to nanoseconds
                timestamp_ns = int(ts * 1_000_000_000)
                size = len(buf)
                eth = dpkt.ethernet.Ethernet(buf)
                
                src_ip = dst_ip = None
                
                if isinstance(eth.data, dpkt.ip.IP):
                    src_ip = inet_to_str(eth.data.src)
                    dst_ip = inet_to_str(eth.data.dst)
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    src_ip = inet_to_str(eth.data.src)
                    dst_ip = inet_to_str(eth.data.dst)
                
                if src_ip and dst_ip:
                    packets.append((timestamp_ns, size, src_ip, dst_ip))
                    
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
    
    return packets


def find_packets_in_window(packets, start_ns, duration_ns):
    """Find packets within exact time window (nanosecond precision)"""
    end_ns = start_ns + duration_ns
    
    matching = []
    for timestamp_ns, size, src_ip, dst_ip in packets:
        if start_ns <= timestamp_ns <= end_ns:
            matching.append((size, src_ip, dst_ip))
    
    return matching


def calculate_metrics(packets):
    """Calculate network metrics from packets"""
    bytes_in = 0
    bytes_out = 0
    
    for size, src_ip, dst_ip in packets:
        if dst_ip in TEST_IPS:
            bytes_in += size
        elif src_ip in TEST_IPS:
            bytes_out += size
    
    return {
        'pcap_network_bytes_in': bytes_in,
        'pcap_network_bytes_out': bytes_out,
        'pcap_overhead_bytes': bytes_in + bytes_out
    }


def parse_timestamp_to_ns(ts_str):
    """Parse ISO timestamp to nanoseconds since epoch"""
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        # Convert to nanoseconds since epoch
        return int(dt.timestamp() * 1_000_000_000)
    except ValueError:
        return None


def enhance_csv(csv_path, pcap_path, output_path, debug=False):
    """Add PCAP metrics to CSV"""
    if not os.path.exists(pcap_path):
        print(f"⚠️  PCAP not found: {pcap_path}")
        return False
    
    print(f"Processing: {os.path.basename(csv_path)}")
    
    # Read PCAP
    try:
        packets = read_pcap(pcap_path)
        print(f"  Loaded {len(packets)} packets")
        
        if packets and debug:
            first_pcap_ns = packets[0][0]
            last_pcap_ns = packets[-1][0]
            print(f"  First PCAP packet: {first_pcap_ns} ns")
            print(f"  Last PCAP packet:  {last_pcap_ns} ns")
            print(f"  PCAP duration: {(last_pcap_ns - first_pcap_ns) / 1e9:.3f}s")
            
    except Exception as e:
        print(f"  ❌ Error reading PCAP: {e}")
        return False
    
    if not packets:
        print("  ❌ No packets found")
        return False
    
    # Read CSV
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) + [
            'pcap_network_bytes_in',
            'pcap_network_bytes_out',
            'pcap_overhead_bytes'
        ]
        rows = list(reader)
    
    if rows and debug:
        first_csv_ns = parse_timestamp_to_ns(rows[0]['timestamp'])
        last_csv_ns = parse_timestamp_to_ns(rows[-1]['timestamp'])
        if first_csv_ns and last_csv_ns:
            print(f"  First CSV query:  {first_csv_ns} ns")
            print(f"  Last CSV query:   {last_csv_ns} ns")
            print(f"  CSV duration: {(last_csv_ns - first_csv_ns) / 1e9:.3f}s")
            
            # Check alignment
            offset_ns = packets[0][0] - first_csv_ns
            print(f"  Time offset (PCAP - CSV): {offset_ns / 1e9:.3f}s")
    
    # Enhance rows
    enhanced = []
    matched = 0
    
    for i, row in enumerate(rows):
        ts_ns = parse_timestamp_to_ns(row['timestamp'])
        if not ts_ns:
            continue
        
        duration_ns = int(row.get('duration_ns', 0))
        
        matching_packets = find_packets_in_window(packets, ts_ns, duration_ns)
        
        metrics = calculate_metrics(matching_packets)
        row.update(metrics)
        enhanced.append(row)
        
        if metrics['pcap_overhead_bytes'] > 0:
            matched += 1
        
        # Debug first few queries
        if debug and i < 3:
            print(f"  Query {i}: {row['domain']}")
            print(f"    Start: {ts_ns} ns")
            print(f"    Duration: {duration_ns} ns ({duration_ns / 1e6:.3f}ms)")
            print(f"    End: {ts_ns + duration_ns} ns")
            print(f"    Matched packets: {len(matching_packets)}")
            print(f"    Bytes: {metrics['pcap_overhead_bytes']}")
    
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
    parser.add_argument('input_dir', help='Input directory (e.g., results_merged)')
    parser.add_argument(
        '--output',
        default='./results_enhanced',
        help='Output directory (default: ./results_enhanced)'
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

#!/usr/bin/env python3
"""
Merge all DNS test CSVs into a single unified CSV.
Extracts metadata from filenames and directory structure.
"""

import csv
from pathlib import Path
from dateutil import parser as date_parser
import argparse


def parse_config(filename: str) -> dict:
    """
    Parse protocol, dnssec_mode, and keep_alive from filename.
    
    Examples:
        doh3-auth.csv         → protocol=doh3, dnssec=auth, persist=0
        tls-trust-persist.csv → protocol=tls, dnssec=trust, persist=1
        https.csv             → protocol=https, dnssec=off, persist=0
        doudp-auth.csv        → protocol=doudp, dnssec=auth, persist=0
        dnscrypt-trust.csv    → protocol=dnscrypt, dnssec=trust, persist=0
    """
    base = filename.replace('.csv', '')
    parts = base.split('-')
    
    protocol = parts[0]
    dnssec_mode = 'off'
    keep_alive = 0
    
    for part in parts[1:]:
        if part in ('auth', 'trust'):
            dnssec_mode = part
        elif part == 'persist':
            keep_alive = 1
    
    return {
        'protocol': protocol,
        'dnssec_mode': dnssec_mode,
        'keep_alive': keep_alive,
    }


def parse_timestamp_unix(ts_str: str) -> float:
    """Convert RFC3339 timestamp to Unix epoch."""
    try:
        dt = date_parser.isoparse(ts_str)
        return dt.timestamp()
    except Exception:
        return 0.0


def ns_to_ms(duration_ns: str) -> float:
    """Convert nanoseconds to milliseconds."""
    try:
        return float(duration_ns) / 1_000_000
    except (ValueError, TypeError):
        return 0.0


def find_csv_files(input_dir: Path) -> list:
    """Find all non-backup CSV files."""
    files = []
    for csv_path in input_dir.rglob('*.csv'):
        name = csv_path.name.lower()
        if '.bak' in name or name.endswith('.cpu.csv') or name.endswith('.mem.csv'):
            continue
        files.append(csv_path)
    return sorted(files)


def merge_all_csvs(input_dir: Path, output_path: Path):
    """Merge all CSVs into a single file."""
    
    csv_files = find_csv_files(input_dir)
    
    if not csv_files:
        print("No CSV files found")
        return
    
    print(f"Found {len(csv_files)} CSV files")
    
    # Output columns in desired order
    output_columns = [
        'id',
        'provider',
        'protocol',
        'dnssec_mode',
        'domain',
        'query_type',
        'keep_alive',
        'dns_server',
        'timestamp',
        'timestamp_unix',
        'duration_ns',
        'duration_ms',
        'request_size_bytes',
        'response_size_bytes',
        'bytes_sent',
        'bytes_received',
        'packets_sent',
        'packets_received',
        'total_bytes',
        'response_code',
        'error',
    ]
    
    global_id = 0
    total_rows = 0
    
    with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=output_columns)
        writer.writeheader()
        
        for csv_path in csv_files:
            # Extract provider from path
            provider = csv_path.parent.name.lower()
            
            # Parse config from filename
            config = parse_config(csv_path.name)
            
            print(f"  {provider}/{csv_path.name} ({config['protocol']}, {config['dnssec_mode']}, persist={config['keep_alive']})")
            
            file_rows = 0
            
            with open(csv_path, 'r', newline='', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                
                for row in reader:
                    global_id += 1
                    file_rows += 1
                    
                    # Build output row
                    out_row = {
                        'id': global_id,
                        'provider': provider,
                        'protocol': config['protocol'],
                        'dnssec_mode': config['dnssec_mode'],
                        'keep_alive': config['keep_alive'],
                        'domain': row.get('domain', ''),
                        'query_type': row.get('query_type', ''),
                        'dns_server': row.get('dns_server', ''),
                        'timestamp': row.get('timestamp', ''),
                        'timestamp_unix': parse_timestamp_unix(row.get('timestamp', '')),
                        'duration_ns': row.get('duration_ns', ''),
                        'duration_ms': ns_to_ms(row.get('duration_ns', '')),
                        'request_size_bytes': row.get('request_size_bytes', ''),
                        'response_size_bytes': row.get('response_size_bytes', ''),
                        'bytes_sent': row.get('bytes_sent', ''),
                        'bytes_received': row.get('bytes_received', ''),
                        'packets_sent': row.get('packets_sent', ''),
                        'packets_received': row.get('packets_received', ''),
                        'total_bytes': row.get('total_bytes', ''),
                        'response_code': row.get('response_code', ''),
                        'error': row.get('error', ''),
                    }
                    
                    writer.writerow(out_row)
            
            total_rows += file_rows
            print(f"    → {file_rows:,} rows")
    
    print(f"\n{'='*60}")
    print(f"Output: {output_path}")
    print(f"Total rows: {total_rows:,}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description='Merge all DNS test CSVs into a single file'
    )
    parser.add_argument(
        'input_dir',
        nargs='?',
        default='.',
        help='Input directory containing provider folders (default: .)'
    )
    parser.add_argument(
        '-o', '--output',
        default='dns_results.csv',
        help='Output CSV path (default: dns_results.csv)'
    )
    
    args = parser.parse_args()
    
    input_dir = Path(args.input_dir)
    output_path = Path(args.output)
    
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        return 1
    
    print("="*60)
    print("MERGE ALL DNS CSVs")
    print("="*60)
    print(f"Input:  {input_dir}")
    print(f"Output: {output_path}")
    print()
    
    merge_all_csvs(input_dir, output_path)
    
    return 0


if __name__ == '__main__':
    exit(main())

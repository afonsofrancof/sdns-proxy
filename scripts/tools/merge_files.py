#!/usr/bin/env python3
"""
Merge DNS test files by configuration.

- Merges CSVs of same config (adds 'run_id' column for traceability)
- Optionally merges PCAPs using mergecap
- Flattens date structure
"""

import os
import csv
import subprocess
import shutil
from pathlib import Path
import argparse
from collections import defaultdict

def parse_filename(filename):
    """
    Extract config key from filename.
    Format: protocol[-flags]-timestamp.{csv,pcap}
    Config key: protocol[-flags] (ignores timestamp)
    """
    base = filename.replace('.csv', '').replace('.pcap', '')
    parts = base.split('-')
    
    if len(parts) < 2:
        return None
    
    # Config is everything except timestamp
    config = '-'.join(parts[:-1])
    timestamp = parts[-1]
    
    return config, timestamp

def extract_resolver_from_path(file_path):
    """Extract resolver name from path"""
    parts = Path(file_path).parts
    for part in parts:
        if part.lower() in ['cloudflare', 'google', 'quad9', 'adguard']:
            return part.lower()
    return None

def find_files(root_dir, extension):
    """Find all files with given extension"""
    files = []
    for root, dirs, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(extension):
                full_path = os.path.join(root, filename)
                files.append(full_path)
    return sorted(files)

def merge_csvs(csv_files, output_path, fieldnames):
    """Merge multiple CSVs into one, adding 'run_id' column"""
    with open(output_path, 'w', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames + ['run_id'])
        writer.writeheader()
        
        for csv_path in csv_files:
            # Use timestamp as run_id
            filename = Path(csv_path).name
            _, timestamp = parse_filename(filename)
            run_id = timestamp  # Or add date if needed
            
            with open(csv_path, 'r', newline='') as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    row['run_id'] = run_id
                    writer.writerow(row)

def merge_pcaps(pcap_files, output_path):
    """Merge PCAP files using mergecap"""
    cmd = ['mergecap', '-w', output_path] + pcap_files
    try:
        subprocess.run(cmd, capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ✗ mergecap error: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        print("Error: mergecap not found. Install Wireshark:")
        print("  Ubuntu: sudo apt install wireshark-common")
        print("  macOS: brew install wireshark")
        return False

def format_bytes(bytes_val):
    """Format bytes as human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} TB"

def main():
    parser = argparse.ArgumentParser(
        description='Merge DNS test files by configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Merges files of same config across dates/timestamps.
Output: ./results_merged/[resolver]/[config].csv (merged)
        ./results_merged/[resolver]/[config].pcap (merged, if --merge-pcaps)

Examples:
  # Dry run to preview
  %(prog)s ./results --dry-run
  
  # Merge CSVs only (recommended)
  %(prog)s ./results
  
  # Merge CSVs and PCAPs
  %(prog)s ./results --merge-pcaps
  
  # Custom output directory
  %(prog)s ./results --output ./merged_data
        '''
    )
    
    parser.add_argument(
        'input_dir',
        help='Input directory (e.g., ./results)'
    )
    parser.add_argument(
        '--output',
        default='./results_merged',
        help='Output directory (default: ./results_merged)'
    )
    parser.add_argument(
        '--merge-pcaps',
        action='store_true',
        help='Merge PCAP files (requires mergecap from Wireshark)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without merging'
    )
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Skip confirmation prompt'
    )
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory not found: {args.input_dir}")
        return 1
    
    # Find all files
    print("=" * 80)
    print("MERGE DNS TEST FILES")
    print("=" * 80)
    print(f"Input:  {args.input_dir}")
    print(f"Output: {args.output}")
    print(f"Merge PCAPs: {'Yes' if args.merge_pcaps else 'No'}")
    
    csv_files = find_files(args.input_dir, '.csv')
    pcap_files = find_files(args.input_dir, '.pcap') if args.merge_pcaps else []
    
    if not csv_files and not pcap_files:
        print("\nNo CSV/PCAP files found")
        return 1
    
    print(f"\nFound {len(csv_files)} CSV files")
    if args.merge_pcaps:
        print(f"Found {len(pcap_files)} PCAP files")
    
    # Group files by resolver and config
    csv_groups = defaultdict(list)
    pcap_groups = defaultdict(list)
    
    for csv_path in csv_files:
        config, _ = parse_filename(Path(csv_path).name)
        resolver = extract_resolver_from_path(csv_path)
        if config and resolver:
            key = (resolver, config)
            csv_groups[key].append(csv_path)
    
    for pcap_path in pcap_files:
        config, _ = parse_filename(Path(pcap_path).name)
        resolver = extract_resolver_from_path(pcap_path)
        if config and resolver:
            key = (resolver, config)
            pcap_groups[key].append(pcap_path)
    
    # Summary
    print("\nConfigs to merge:")
    print("-" * 80)
    for (resolver, config), files in sorted(csv_groups.items()):
        print(f"  {resolver}/{config}: {len(files)} runs")
    
    total_runs = sum(len(files) for files in csv_groups.values())
    print(f"\nTotal configs: {len(csv_groups)}")
    print(f"Total runs:    {total_runs}")
    
    if args.dry_run:
        print("\n*** DRY RUN MODE ***\n")
        for (resolver, config) in sorted(csv_groups.keys()):
            print(f"Would merge: {resolver}/{config} ({len(csv_groups[(resolver, config)])} CSVs)")
            if args.merge_pcaps and (resolver, config) in pcap_groups:
                print(f"Would merge: {resolver}/{config} ({len(pcap_groups[(resolver, config)])} PCAPs)")
        return 0
    
    # Confirmation
    if not args.yes:
        response = input(f"\nMerge all into {args.output}? [y/N] ")
        if response.lower() not in ['y', 'yes']:
            print("Cancelled")
            return 0
    
    # Merge
    print("\n" + "=" * 80)
    print("MERGING FILES")
    print("=" * 80)
    
    success_count = 0
    fail_count = 0
    total_queries = 0
    total_size = 0
    
    # Get standard CSV fieldnames (from first file)
    first_csv = next(iter(csv_files))
    with open(first_csv, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
    
    for (resolver, config), files in sorted(csv_groups.items()):
        print(f"\n{resolver}/{config} ({len(files)} runs)")
        
        # Merge CSVs
        output_csv = os.path.join(args.output, resolver, f"{config}.csv")
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        
        merge_csvs(files, output_csv, fieldnames)
        
        # Count queries in merged file
        with open(output_csv, 'r') as f:
            query_count = sum(1 for _ in csv.reader(f)) - 1  # Minus header
        
        print(f"  ✓ Merged CSV: {query_count:,} queries")
        total_queries += query_count
        success_count += 1
        
        # Merge PCAPs if requested
        if args.merge_pcaps and (resolver, config) in pcap_groups:
            output_pcap = os.path.join(args.output, resolver, f"{config}.pcap")
            pcap_list = pcap_groups[(resolver, config)]
            
            if merge_pcaps(pcap_list, output_pcap):
                merged_size = os.path.getsize(output_pcap)
                orig_size = sum(os.path.getsize(p) for p in pcap_list)
                print(f"  ✓ Merged PCAP: {format_bytes(merged_size)} "
                      f"(from {format_bytes(orig_size)})")
                total_size += merged_size
            else:
                print(f"  ✗ PCAP merge failed")
                fail_count += 1
    
    # Final summary
    print("\n" + "=" * 80)
    print("COMPLETE")
    print("=" * 80)
    print(f"Successful configs: {success_count}")
    print(f"Failed:            {fail_count}")
    print(f"Total queries:     {total_queries:,}")
    if args.merge_pcaps:
        print(f"Total PCAP size:   {format_bytes(total_size)}")
    print(f"\nMerged files in: {args.output}")
    
    return 0 if fail_count == 0 else 1

if __name__ == "__main__":
    exit(main())

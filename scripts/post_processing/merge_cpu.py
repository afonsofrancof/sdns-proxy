#!/usr/bin/env python3
"""
Merge all .cpu.csv files into a single unified CPU metrics CSV.
Adds provider, protocol, dnssec_mode, keep_alive columns.
"""

import csv
import argparse
from pathlib import Path
from typing import List


def parse_config_from_filename(filename: str) -> dict:
    """Parse protocol, dnssec_mode, keep_alive from filename like 'dot-trust-persist.cpu.csv'"""
    base = filename.replace('.cpu.csv', '').replace('.CPU.csv', '')
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


def find_cpu_files(input_dir: Path):
    files: List[Path] = []
    for p in input_dir.rglob('*.cpu.csv'):
        if '.bak' not in p.name:
            files.append(p)
    return sorted(files)


def merge_cpu_files(input_dir: Path, output_path: Path):
    cpu_files = find_cpu_files(input_dir)
    
    if not cpu_files:
        print("No .cpu.csv files found")
        return
    
    print(f"Found {len(cpu_files)} CPU metric files")
    
    output_columns = [
        'id','provider', 'protocol', 'dnssec_mode', 'keep_alive',
        'timestamp', 'wall_time_seconds', 'instructions', 'cycles', 'peak_rss_kb'
    ]
    
    total_rows = 0
    
    with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=output_columns)
        writer.writeheader()
        
        for cpu_path in cpu_files:
            provider = cpu_path.parent.name.lower()
            config = parse_config_from_filename(cpu_path.name)
            
            print(f"  {provider}/{cpu_path.name} "
                  f"({config['protocol']}, {config['dnssec_mode']}, persist={config['keep_alive']})")
            
            with open(cpu_path, 'r', newline='', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    total_rows += 1
                    out_row = {
                        'id': total_rows,
                        'provider': provider,
                        'protocol': config['protocol'],
                        'dnssec_mode': config['dnssec_mode'],
                        'keep_alive': config['keep_alive'],
                        'timestamp': row.get('timestamp', ''),
                        'wall_time_seconds': row.get('wall_time_seconds', ''),
                        'instructions': row.get('instructions', ''),
                        'cycles': row.get('cycles', ''),
                        'peak_rss_kb': row.get('peak_rss_kb', ''),
                    }
                    writer.writerow(out_row)
    
    print(f"\n{'='*60}")
    print(f"CPU metrics merged → {output_path}")
    print(f"Total run records: {total_rows}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description='Merge all .cpu.csv files')
    parser.add_argument('input_dir', nargs='?', default='.', help='Input directory')
    parser.add_argument('-o', '--output', default='dns_results_cpu.csv', help='Output path')
    args = parser.parse_args()
    
    merge_cpu_files(Path(args.input_dir), Path(args.output))
    return 0


if __name__ == '__main__':
    exit(main())

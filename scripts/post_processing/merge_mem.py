#!/usr/bin/env python3
"""
Merge all .mem.csv files into a single unified Memory metrics CSV.
Adds provider, protocol, dnssec_mode, keep_alive columns.
"""

import csv
import argparse
from pathlib import Path
from typing import List


def parse_config_from_filename(filename: str) -> dict:
    """Parse protocol, dnssec_mode, keep_alive from filename"""
    base = filename.replace('.mem.csv', '').replace('.MEM.csv', '')
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


def find_mem_files(input_dir: Path):
    files: List[Path] = []
    for p in input_dir.rglob('*.mem.csv'):
        if '.bak' not in p.name:
            files.append(p)
    return sorted(files)


def merge_mem_files(input_dir: Path, output_path: Path):
    mem_files = find_mem_files(input_dir)
    
    if not mem_files:
        print("No .mem.csv files found")
        return
    
    print(f"Found {len(mem_files)} Memory metric files")
    
    output_columns = [
        'id',' provider', 'protocol', 'dnssec_mode', 'keep_alive',
        'timestamp', 'total_alloc_bytes', 'mallocs', 'gc_cycles',
        'alloc_delta', 'mallocs_delta', 'gc_delta'
    ]
    
    total_rows = 0
    
    with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=output_columns)
        writer.writeheader()
        
        for mem_path in mem_files:
            provider = mem_path.parent.name.lower()
            config = parse_config_from_filename(mem_path.name)
            
            print(f"  {provider}/{mem_path.name} "
                  f"({config['protocol']}, {config['dnssec_mode']}, persist={config['keep_alive']})")
            
            with open(mem_path, 'r', newline='', encoding='utf-8') as infile:
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
                        'total_alloc_bytes': row.get('total_alloc_bytes', ''),
                        'mallocs': row.get('mallocs', ''),
                        'gc_cycles': row.get('gc_cycles', ''),
                        'alloc_delta': row.get('alloc_delta', ''),
                        'mallocs_delta': row.get('mallocs_delta', ''),
                        'gc_delta': row.get('gc_delta', ''),
                    }
                    writer.writerow(out_row)
    
    print(f"\n{'='*60}")
    print(f"Memory metrics merged → {output_path}")
    print(f"Total run records: {total_rows}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description='Merge all .mem.csv files')
    parser.add_argument('input_dir', nargs='?', default='.', help='Input directory')
    parser.add_argument('-o', '--output', default='dns_results_mem.csv', help='Output path')
    args = parser.parse_args()
    
    merge_mem_files(Path(args.input_dir), Path(args.output))
    return 0


if __name__ == '__main__':
    exit(main())

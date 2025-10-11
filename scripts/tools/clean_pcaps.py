#!/usr/bin/env python3
"""
Advanced PCAP filter for DNS traffic (with IPv6 support).

Filters out:
- Local network traffic except test machine (IPv4: 10.0.0.50; IPv6: specific addresses)
- AdGuard DNS servers (for non-AdGuard captures)
- Non-DNS traffic based on protocol-specific ports
"""

import os
import subprocess
from pathlib import Path
import argparse

# Test machine IPs (IPv4 and IPv6 from your provided info)
TEST_IPV4 = '10.0.0.50'
TEST_IPV6_GLOBAL = '2001:818:e73e:ba00:5506:dfd4:ed8b:96e'
TEST_IPV6_LINKLOCAL = 'fe80::fe98:c62e:4463:9a2d'

# Port mappings
PORT_MAP = {
    'udp': [53],                    # DNS-over-UDP
    'tls': [53, 853],               # DNS-over-TLS
    'https': [53, 443],             # DNS-over-HTTPS (DoH)
    'doq': [53, 784, 8853],         # DNS-over-QUIC
    'doh3': [53, 443]               # DNS-over-HTTP/3
}

# AdGuard DNS IPs to filter out (for non-AdGuard captures)
ADGUARD_IPS = [
    '94.140.14.14',
    '94.140.15.15',
    '2a10:50c0::ad1:ff',
    '2a10:50c0::ad2:ff'
]

def parse_filename(filename):
    """Extract protocol from filename"""
    base = filename.replace('.pcap', '').replace('.csv', '')
    parts = base.split('-')
    
    if len(parts) < 1:  # Minimum: protocol
        return None
    
    protocol = parts[0].lower()
    return protocol

def extract_resolver_from_path(pcap_path):
    """Extract resolver name from directory structure"""
    parts = Path(pcap_path).parts
    
    for part in parts:
        if part.lower() in ['cloudflare', 'google', 'quad9', 'adguard']:
            return part.lower()
    
    return None

def build_filter_expression(protocol, resolver):
    """
    Build tshark filter expression.
    
    Strategy:
    1. Only protocol-specific DNS ports
    2. Keep only traffic involving the test machine (IPv4/IPv6)
    3. Exclude AdGuard IPs for non-AdGuard captures
    """
    
    # Get ports for this protocol
    ports = PORT_MAP.get(protocol, [53, 443, 853, 784, 8853])
    
    # Build port filter (UDP or TCP on these ports)
    port_conditions = []
    for port in ports:
        port_conditions.append(f'(udp.port == {port} or tcp.port == {port})')
    
    port_filter = ' or '.join(port_conditions)
    
    # Build test machine filter (keep if src or dst is test machine IP)
    machine_conditions = [f'(ip.addr == {TEST_IPV4})']
    if TEST_IPV6_GLOBAL:
        machine_conditions.append(f'(ipv6.addr == {TEST_IPV6_GLOBAL})')
    if TEST_IPV6_LINKLOCAL:
        machine_conditions.append(f'(ipv6.addr == {TEST_IPV6_LINKLOCAL})')
    
    machine_filter = ' or '.join(machine_conditions)
    
    # Build AdGuard exclusion filter
    adguard_exclusions = []
    if resolver != 'adguard':
        for ip in ADGUARD_IPS:
            if ':' in ip:  # IPv6
                adguard_exclusions.append(f'!(ipv6.addr == {ip})')
            else:  # IPv4
                adguard_exclusions.append(f'!(ip.addr == {ip})')
    
    # Combine all filters
    filters = [f'({port_filter})', f'({machine_filter})']
    
    if adguard_exclusions:
        adguard_filter = ' and '.join(adguard_exclusions)
        filters.append(f'({adguard_filter})')
    
    final_filter = ' and '.join(filters)
    
    return final_filter

def filter_pcap(input_path, output_path, filter_expr, verbose=False):
    """Apply filter to PCAP file using tshark"""
    
    cmd = [
        'tshark',
        '-r', input_path,
        '-Y', filter_expr,
        '-w', output_path,
        '-F', 'pcap'
    ]
    
    try:
        if verbose:
            print(f"  Filter: {filter_expr}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            print(f"  ✗ Error: {result.stderr.strip()}")
            return False
        
        if not os.path.exists(output_path):
            print(f"  ✗ Output file not created")
            return False
        
        output_size = os.path.getsize(output_path)
        if output_size < 24:
            print(f"  ⚠ Warning: Output is empty")
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"  ✗ Timeout (>5 minutes)")
        return False
    except Exception as e:
        print(f"  ✗ Exception: {e}")
        return False

def find_pcap_files(root_dir):
    """Recursively find all PCAP files"""
    pcap_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.pcap'):
                full_path = os.path.join(root, file)
                pcap_files.append(full_path)
    return sorted(pcap_files)

def format_bytes(bytes_val):
    """Format bytes as human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} TB"

def main():
    parser = argparse.ArgumentParser(
        description='Advanced PCAP filter for DNS traffic (IPv4/IPv6)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Filtering rules:
  1. Only include traffic on protocol-specific DNS ports
  2. Keep only packets involving the test machine (10.0.0.50 or its IPv6 addresses)
  3. Exclude AdGuard IPs for non-AdGuard captures

Protocol-specific ports:
  udp:   53
  tls:   53, 853
  https: 53, 443
  doq:   53, 784, 8853
  doh3:  53, 443

Examples:
  # Dry run
  %(prog)s ./results --dry-run
  
  # Filter with verbose output
  %(prog)s ./results --verbose
  
  # Custom output directory
  %(prog)s ./results --output ./cleaned
        '''
    )
    
    parser.add_argument(
        'input_dir',
        help='Input directory containing PCAP files'
    )
    parser.add_argument(
        '-o', '--output',
        default='./results_filtered',
        help='Output directory (default: ./results_filtered)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without filtering'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Only process first N files (for testing)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output (show filter expressions)'
    )
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Overwrite existing filtered files'
    )
    
    args = parser.parse_args()
    
    # Check for tshark
    try:
        result = subprocess.run(
            ['tshark', '-v'],
            capture_output=True,
            check=True
        )
        if args.verbose:
            version = result.stdout.decode().split('\n')[0]
            print(f"Using: {version}\n")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: tshark not found. Install Wireshark/tshark:")
        print("  Ubuntu/Debian: sudo apt-get install tshark")
        print("  macOS: brew install wireshark")
        return 1
    
    print("=" * 80)
    print("ADVANCED DNS PCAP FILTER (IPv4/IPv6)")
    print("=" * 80)
    print("Filters:")
    print("  1. Protocol-specific DNS ports only")
    print("  2. Keep only traffic involving test machine (10.0.0.50 / IPv6 addresses)")
    print("  3. Exclude AdGuard IPs (for non-AdGuard captures)")
    print(f"\nInput:  {args.input_dir}")
    print(f"Output: {args.output}")
    
    # Find PCAP files
    print(f"\nScanning for PCAP files...")
    pcap_files = find_pcap_files(args.input_dir)
    
    if not pcap_files:
        print(f"No PCAP files found in {args.input_dir}")
        return 1
    
    print(f"Found {len(pcap_files)} PCAP files")
    
    total_input_size = sum(os.path.getsize(f) for f in pcap_files)
    print(f"Total size: {format_bytes(total_input_size)}")
    
    if args.limit:
        pcap_files = pcap_files[:args.limit]
        print(f"Limiting to first {args.limit} files")
    
    if args.dry_run:
        print("\n*** DRY RUN MODE ***\n")
    else:
        print()
    
    # Process files
    success_count = 0
    skip_count = 0
    fail_count = 0
    total_output_size = 0
    
    for i, input_path in enumerate(pcap_files, 1):
        # Extract info from path
        filename = Path(input_path).name
        protocol = parse_filename(filename)
        resolver = extract_resolver_from_path(input_path)
        
        if not protocol:
            print(f"[{i}/{len(pcap_files)}] {filename}")
            print(f"  ⚠ Could not parse protocol, skipping")
            skip_count += 1
            continue
        
        # Create output path
        rel_path = os.path.relpath(input_path, args.input_dir)
        output_path = os.path.join(args.output, rel_path)
        
        input_size = os.path.getsize(input_path)
        
        print(f"[{i}/{len(pcap_files)}] {rel_path}")
        print(f"  Protocol: {protocol.upper()}")
        print(f"  Resolver: {resolver or 'unknown'}")
        print(f"  Size: {format_bytes(input_size)}")
        
        # Check if already filtered
        if os.path.exists(output_path) and not args.overwrite:
            output_size = os.path.getsize(output_path)
            reduction = ((input_size - output_size) / input_size * 100) if input_size > 0 else 0
            print(f"  ⊙ Already filtered: {format_bytes(output_size)} "
                  f"({reduction:.1f}% reduction)")
            skip_count += 1
            total_output_size += output_size
            continue
        
        # Build filter
        filter_expr = build_filter_expression(protocol, resolver)
        
        if args.dry_run:
            print(f"  → Would filter")
            if args.verbose:
                print(f"  Filter: {filter_expr}")
            continue
        
        # Create output directory
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Filter
        success = filter_pcap(input_path, output_path, filter_expr, args.verbose)
        
        if success:
            output_size = os.path.getsize(output_path)
            reduction = ((input_size - output_size) / input_size * 100) if input_size > 0 else 0
            print(f"  ✓ Filtered: {format_bytes(output_size)} "
                  f"({reduction:.1f}% reduction)")
            success_count += 1
            total_output_size += output_size
        else:
            fail_count += 1
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    if args.dry_run:
        print(f"Would process: {len(pcap_files)} files")
    else:
        print(f"Successful:    {success_count}")
        print(f"Skipped:       {skip_count} (already filtered or unparseable)")
        print(f"Failed:        {fail_count}")
        print(f"Total:         {len(pcap_files)}")
        
        if success_count > 0 or skip_count > 0:
            print(f"\nInput size:    {format_bytes(total_input_size)}")
            print(f"Output size:   {format_bytes(total_output_size)}")
            if total_input_size > 0:
                reduction = ((total_input_size - total_output_size) / 
                            total_input_size * 100)
                print(f"Reduction:     {reduction:.1f}%")
            print(f"\nOutput directory: {args.output}")
    
    return 0 if fail_count == 0 else 1

if __name__ == "__main__":
    exit(main())

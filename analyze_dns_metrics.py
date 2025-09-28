import csv
import os
import statistics
from collections import defaultdict
from pathlib import Path

def map_server_to_resolver(server):
    """Map server address/domain to resolver name"""
    server_lower = server.lower()
    
    if '1.1.1.1' in server_lower or 'cloudflare' in server_lower:
        return 'Cloudflare'
    elif '8.8.8.8' in server_lower or 'dns.google' in server_lower:
        return 'Google'
    elif '9.9.9.9' in server_lower or 'quad9' in server_lower:
        return 'Quad9'
    elif 'adguard' in server_lower:
        return 'AdGuard'
    else:
        return server  # Fallback to original server name

def extract_from_new_format(filename):
    """Parse new filename format: protocol[-flags]-timestamp.csv"""
    base = filename.replace('.csv', '')
    parts = base.split('-')
    
    if len(parts) < 2:
        return None, None, None, None
    
    protocol = parts[0]
    timestamp = parts[-1]
    
    # Flags are everything between protocol and timestamp
    flags_str = '-'.join(parts[1:-1])
    
    # Determine DNSSEC status
    if 'auth' in flags_str:
        dnssec_status = 'auth'  # Authoritative DNSSEC
    elif 'trust' in flags_str:
        dnssec_status = 'trust'  # Trust-based DNSSEC
    else:
        dnssec_status = 'off'
    
    keepalive_status = 'on' if 'persist' in flags_str else 'off'
    
    return protocol, dnssec_status, keepalive_status, flags_str

def extract_server_info_from_csv(row):
    """Extract DNSSEC info from CSV row data"""
    dnssec = row.get('dnssec', 'false').lower() == 'true'
    auth_dnssec = row.get('auth_dnssec', 'false').lower() == 'true'
    keepalive = row.get('keep_alive', 'false').lower() == 'true'
    
    if dnssec:
        if auth_dnssec:
            dnssec_status = 'auth'
        else:
            dnssec_status = 'trust'
    else:
        dnssec_status = 'off'
    
    keepalive_status = 'on' if keepalive else 'off'
    
    return dnssec_status, keepalive_status

def extract_server_info(file_path, row):
    """Extract info using directory structure, filename, and CSV data"""
    path = Path(file_path)
    
    # First try to get DNSSEC info from CSV row (most accurate)
    try:
        csv_dnssec_status, csv_keepalive_status = extract_server_info_from_csv(row)
        protocol = row.get('protocol', '').lower()
        
        # Get server from directory structure
        parts = path.parts
        if len(parts) >= 4:
            potential_date = parts[-2]
            # Check if it's a date like YYYY-MM-DD
            if len(potential_date) == 10 and potential_date[4] == '-' and potential_date[7] == '-' and potential_date.replace('-', '').isdigit():
                server = parts[-3]  # resolver folder (e.g., cloudflare)
                return protocol, server, csv_dnssec_status, csv_keepalive_status
        
        # Fallback to DNS server field
        server = row.get('dns_server', '')
        return protocol, server, csv_dnssec_status, csv_keepalive_status
        
    except (KeyError, ValueError):
        pass
    
    # Fallback to filename parsing
    filename = path.name
    protocol, dnssec_status, keepalive_status, flags = extract_from_new_format(filename)
    
    if protocol:
        # Get server from directory structure
        parts = path.parts
        if len(parts) >= 4:
            potential_date = parts[-2]
            if len(potential_date) == 10 and potential_date[4] == '-' and potential_date[7] == '-' and potential_date.replace('-', '').isdigit():
                server = parts[-3]
                return protocol, server, dnssec_status, keepalive_status
        
        # Fallback to DNS server field
        server = row.get('dns_server', '')
        return protocol, server, dnssec_status, keepalive_status
    
    return None, None, None, None

def get_dnssec_display_name(dnssec_status):
    """Convert DNSSEC status to display name"""
    if dnssec_status == 'auth':
        return 'DNSSEC (Authoritative)'
    elif dnssec_status == 'trust':
        return 'DNSSEC (Trust-based)'
    else:
        return 'No DNSSEC'

def analyze_dns_data(root_directory, output_file):
    """Analyze DNS data and generate metrics"""
    
    # Dictionary to store measurements: {(resolver, protocol, dnssec, keepalive): [durations]}
    measurements = defaultdict(list)
    
    # Walk through all directories
    for root, dirs, files in os.walk(root_directory):
        for file in files:
            if file.endswith('.csv'):
                file_path = os.path.join(root, file)
                print(f"Processing: {file_path}")
                
                try:
                    with open(file_path, 'r', newline='') as csvfile:
                        reader = csv.DictReader(csvfile)
                        
                        for row_num, row in enumerate(reader, 2):  # Start at 2 since header is row 1
                            try:
                                protocol, server, dnssec_status, keepalive_status = extract_server_info(file_path, row)
                                
                                if protocol and server:
                                    resolver = map_server_to_resolver(server)
                                    duration_ms = float(row.get('duration_ms', 0))
                                    
                                    # Only include successful queries
                                    if row.get('response_code', '') in ['NOERROR', '']:
                                        key = (resolver, protocol, dnssec_status, keepalive_status)
                                        measurements[key].append(duration_ms)
                                    
                            except (ValueError, TypeError) as e:
                                print(f"Data parse error in {file_path} row {row_num}: {e}")
                                continue
                                
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
                    continue
    
    # Calculate statistics grouped by resolver first, then by configuration
    resolver_results = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    
    for (resolver, protocol, dnssec, keepalive), durations in measurements.items():
        if durations:
            stats = {
                'protocol': protocol.upper(),
                'dnssec': dnssec,
                'keepalive': keepalive,
                'total_queries': len(durations),
                'avg_latency_ms': round(statistics.mean(durations), 3),
                'median_latency_ms': round(statistics.median(durations), 3),
                'min_latency_ms': round(min(durations), 3),
                'max_latency_ms': round(max(durations), 3),
                'std_dev_ms': round(statistics.stdev(durations) if len(durations) > 1 else 0, 3),
                'p95_latency_ms': round(statistics.quantiles(durations, n=20)[18], 3) if len(durations) >= 20 else round(max(durations), 3),
                'p99_latency_ms': round(statistics.quantiles(durations, n=100)[98], 3) if len(durations) >= 100 else round(max(durations), 3)
            }
            # Group by resolver -> dnssec -> keepalive -> protocol
            resolver_results[resolver][dnssec][keepalive].append(stats)
    
    # Sort each configuration's results by average latency
    for resolver in resolver_results:
        for dnssec in resolver_results[resolver]:
            for keepalive in resolver_results[resolver][dnssec]:
                resolver_results[resolver][dnssec][keepalive].sort(key=lambda x: x['avg_latency_ms'])
    
    # Write to CSV with all data
    all_results = []
    for resolver in resolver_results:
        for dnssec in resolver_results[resolver]:
            for keepalive in resolver_results[resolver][dnssec]:
                for result in resolver_results[resolver][dnssec][keepalive]:
                    result['resolver'] = resolver
                    all_results.append(result)
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            'resolver', 'protocol', 'dnssec', 'keepalive', 'total_queries',
            'avg_latency_ms', 'median_latency_ms', 'min_latency_ms', 
            'max_latency_ms', 'std_dev_ms', 'p95_latency_ms', 'p99_latency_ms'
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)
    
    print(f"\nAnalysis complete! Full results written to {output_file}")
    print(f"Total measurements: {sum(len(durations) for durations in measurements.values())}")
    
    def print_configuration_table(resolver, dnssec_status, keepalive_status, results):
        """Print a formatted table for a specific configuration"""
        ka_indicator = "PERSISTENT" if keepalive_status == 'on' else "NEW CONN"
        dnssec_display = get_dnssec_display_name(dnssec_status)
        
        print(f"\n  {dnssec_display} - {ka_indicator}")
        print("  " + "-" * 90)
        print(f"  {'Protocol':<12} {'Queries':<8} {'Avg(ms)':<10} {'Median(ms)':<12} {'Min(ms)':<10} {'Max(ms)':<10} {'P95(ms)':<10}")
        print("  " + "-" * 90)
        
        for result in results:
            print(f"  {result['protocol']:<12} {result['total_queries']:<8} "
                  f"{result['avg_latency_ms']:<10} {result['median_latency_ms']:<12} "
                  f"{result['min_latency_ms']:<10} {result['max_latency_ms']:<10} "
                  f"{result['p95_latency_ms']:<10}")
    
    # Print results grouped by resolver first
    print(f"\n{'=' * 100}")
    print("DNS RESOLVER PERFORMANCE COMPARISON")
    print(f"{'=' * 100}")
    
    for resolver in sorted(resolver_results.keys()):
        print(f"\n{resolver} DNS Resolver")
        print("=" * 100)
        
        # Order configurations logically
        config_order = [
            ('off', 'off'),     # No DNSSEC, New connections
            ('off', 'on'),      # No DNSSEC, Persistent
            ('trust', 'off'),   # Trust DNSSEC, New connections  
            ('trust', 'on'),    # Trust DNSSEC, Persistent
            ('auth', 'off'),    # Auth DNSSEC, New connections
            ('auth', 'on'),     # Auth DNSSEC, Persistent
        ]
        
        for dnssec_status, keepalive_status in config_order:
            if dnssec_status in resolver_results[resolver] and keepalive_status in resolver_results[resolver][dnssec_status]:
                results = resolver_results[resolver][dnssec_status][keepalive_status]
                if results:  # Only print if there are results
                    print_configuration_table(resolver, dnssec_status, keepalive_status, results)
    
    # Summary comparison across resolvers
    print(f"\n{'=' * 100}")
    print("CROSS-RESOLVER PROTOCOL COMPARISON")
    print(f"{'=' * 100}")
    
    # Group by protocol and configuration for cross-resolver comparison
    protocol_comparison = defaultdict(lambda: defaultdict(list))
    
    for resolver in resolver_results:
        for dnssec in resolver_results[resolver]:
            for keepalive in resolver_results[resolver][dnssec]:
                for result in resolver_results[resolver][dnssec][keepalive]:
                    config_key = f"{get_dnssec_display_name(dnssec)} - {'PERSISTENT' if keepalive == 'on' else 'NEW CONN'}"
                    protocol_comparison[result['protocol']][config_key].append({
                        'resolver': resolver,
                        'avg_latency_ms': result['avg_latency_ms'],
                        'total_queries': result['total_queries']
                    })
    
    for protocol in sorted(protocol_comparison.keys()):
        print(f"\n{protocol} Protocol Comparison")
        print("-" * 100)
        
        for config in sorted(protocol_comparison[protocol].keys()):
            resolvers_data = protocol_comparison[protocol][config]
            if resolvers_data:
                print(f"\n  {config}")
                print("  " + "-" * 60)
                print(f"  {'Resolver':<15} {'Avg Latency (ms)':<20} {'Queries':<10}")
                print("  " + "-" * 60)
                
                # Sort by average latency
                resolvers_data.sort(key=lambda x: x['avg_latency_ms'])
                
                for data in resolvers_data:
                    print(f"  {data['resolver']:<15} {data['avg_latency_ms']:<20} {data['total_queries']:<10}")

if __name__ == "__main__":
    root_dir = "."
    output_file = "dns_metrics.csv"
    
    analyze_dns_data(root_dir, output_file)

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
        return server

def extract_from_new_format(filename):
    """Parse new filename format: protocol[-flags]-timestamp.csv"""
    base = filename.replace('.csv', '')
    parts = base.split('-')
    
    if len(parts) < 2:
        return None, None, None
    
    protocol = parts[0]
    timestamp = parts[-1]
    
    # Flags are everything between protocol and timestamp
    flags_str = '-'.join(parts[1:-1])
    dnssec_status = 'on' if 'dnssec' in flags_str else 'off'
    keepalive_status = 'on' if 'persist' in flags_str else 'off'
    
    return protocol, dnssec_status, keepalive_status

def extract_server_info(file_path, dns_server_field):
    """Extract info using directory structure and filename"""
    path = Path(file_path)
    
    # Expect structure like: results/resolver/date/filename.csv
    parts = path.parts
    if len(parts) >= 3 and parts[-2].isdigit() and len(parts[-2]) == 10:  # date folder like 2024-03-01
        server = parts[-3]  # resolver folder (e.g., cloudflare)
        filename = parts[-1]
        
        protocol, dnssec_status, keepalive_status = extract_from_new_format(filename)
        if protocol:
            return protocol, server, dnssec_status, keepalive_status
    
    # Fallback to old parsing if structure doesn't match
    filename = path.name
    old_parts = filename.replace('.csv', '').split('_')
    
    if len(old_parts) >= 6:
        protocol = old_parts[0]
        
        try:
            dnssec_idx = old_parts.index('dnssec')
            keepalive_idx = old_parts.index('keepalive')
            
            server_parts = old_parts[1:dnssec_idx]
            server = '_'.join(server_parts)
            
            dnssec_status = old_parts[dnssec_idx + 1] if dnssec_idx + 1 < len(old_parts) else 'off'
            keepalive_status = old_parts[keepalive_idx + 1] if keepalive_idx + 1 < len(old_parts) else 'off'
            
            return protocol, server, dnssec_status, keepalive_status
            
        except ValueError:
            pass
    
    # Even older format fallback
    if len(old_parts) >= 4:
        protocol = old_parts[0]
        dnssec_status = 'on' if 'dnssec_on' in filename else 'off'
        keepalive_status = 'on' if 'keepalive_on' in filename else 'off'
        server = '_'.join(old_parts[1:-4]) if len(old_parts) > 4 else old_parts[1]
        
        return protocol, server, dnssec_status, keepalive_status
    
    return None, None, None, None

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
                                protocol, server, dnssec_status, keepalive_status = extract_server_info(
                                    file_path, row.get('dns_server', ''))
                                
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
    
    # Calculate statistics and group by resolver, dnssec, and keepalive
    resolver_results = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    
    for (resolver, protocol, dnssec, keepalive), durations in measurements.items():
        if durations:
            stats = {
                'protocol': protocol.upper(),
                'total_queries': len(durations),
                'avg_latency_ms': round(statistics.mean(durations), 3),
                'median_latency_ms': round(statistics.median(durations), 3),
                'min_latency_ms': round(min(durations), 3),
                'max_latency_ms': round(max(durations), 3),
                'std_dev_ms': round(statistics.stdev(durations) if len(durations) > 1 else 0, 3),
                'p95_latency_ms': round(statistics.quantiles(durations, n=20)[18], 3) if len(durations) >= 20 else round(max(durations), 3),
                'p99_latency_ms': round(statistics.quantiles(durations, n=100)[98], 3) if len(durations) >= 100 else round(max(durations), 3)
            }
            resolver_results[dnssec][keepalive][resolver].append(stats)
    
    # Sort each resolver's results by average latency
    for dnssec in resolver_results:
        for keepalive in resolver_results[dnssec]:
            for resolver in resolver_results[dnssec][keepalive]:
                resolver_results[dnssec][keepalive][resolver].sort(key=lambda x: x['avg_latency_ms'])
    
    # Write to CSV with all data
    all_results = []
    for dnssec in resolver_results:
        for keepalive in resolver_results[dnssec]:
            for resolver, results in resolver_results[dnssec][keepalive].items():
                for result in results:
                    result['resolver'] = resolver
                    result['dnssec'] = dnssec
                    result['keepalive'] = keepalive
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
    
    def print_resolver_table(resolver, results, dnssec_status, keepalive_status):
        """Print a formatted table for a resolver"""
        ka_indicator = "PERSISTENT" if keepalive_status == 'on' else "NEW CONNECTION"
        print(f"\n{resolver} DNS Resolver (DNSSEC {dnssec_status.upper()}, {ka_indicator})")
        print("=" * 100)
        print(f"{'Protocol':<12} {'Queries':<8} {'Avg(ms)':<10} {'Median(ms)':<12} {'Min(ms)':<10} {'Max(ms)':<10} {'P95(ms)':<10}")
        print("-" * 100)
        
        for result in results:
            print(f"{result['protocol']:<12} {result['total_queries']:<8} "
                  f"{result['avg_latency_ms']:<10} {result['median_latency_ms']:<12} "
                  f"{result['min_latency_ms']:<10} {result['max_latency_ms']:<10} "
                  f"{result['p95_latency_ms']:<10}")
    
    # Print tables organized by DNSSEC and KeepAlive status
    for dnssec_status in ['off', 'on']:
        if dnssec_status in resolver_results:
            print(f"\n{'#' * 60}")
            print(f"# DNS RESOLVERS - DNSSEC {dnssec_status.upper()}")
            print(f"{'#' * 60}")
            
            for keepalive_status in ['off', 'on']:
                if keepalive_status in resolver_results[dnssec_status]:
                    for resolver in sorted(resolver_results[dnssec_status][keepalive_status].keys()):
                        results = resolver_results[dnssec_status][keepalive_status][resolver]
                        print_resolver_table(resolver, results, dnssec_status, keepalive_status)

if __name__ == "__main__":
    root_dir = "."
    output_file = "dns_metrics.csv"
    
    analyze_dns_data(root_dir, output_file)

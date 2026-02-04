import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
import datetime
from dateutil import parser as date_parser
import dpkt

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10

class FastDNSAnalyzer:
    def __init__(self, results_dir='results'):
        self.results_dir = Path(results_dir)
        self.all_data = []
        
    def should_include_file(self, filename):
        """Filter out DNSSEC and non-persist files"""
        name = filename.stem
        if 'auth' in name or 'trust' in name:
            return False
        if name in ['tls', 'https']:
            return False
        return True
    
    def parse_rfc3339_nano(self, timestamp_str):
        """Parse RFC3339Nano timestamp with timezone"""
        try:
            dt = date_parser.parse(timestamp_str)
            return dt.astimezone(datetime.timezone.utc).timestamp()
        except Exception as e:
            print(f"    Error parsing timestamp {timestamp_str}: {e}")
            return None
    
    def extract_bandwidth_from_pcap_fast(self, pcap_file, csv_data):
        """Fast bandwidth extraction using dpkt"""
        print(f"    Analyzing pcap: {pcap_file.name}")
        
        try:
            with open(pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                # Build query time windows
                query_windows = []
                for idx, row in csv_data.iterrows():
                    start_time = self.parse_rfc3339_nano(row['timestamp'])
                    if start_time is None:
                        continue
                    
                    duration_seconds = row['duration_ns'] / 1_000_000_000
                    end_time = start_time + duration_seconds
                    
                    query_windows.append({
                        'index': idx,
                        'start': start_time,
                        'end': end_time,
                        'bytes_sent': 0,
                        'bytes_received': 0,
                        'packets_sent': 0,
                        'packets_received': 0
                    })
                
                if not query_windows:
                    print("    ✗ No valid query windows")
                    return None
                
                # Sort windows for faster matching
                query_windows.sort(key=lambda x: x['start'])
                
                # Process packets
                packet_count = 0
                matched_count = 0
                
                for timestamp, buf in pcap:
                    packet_count += 1
                    packet_size = len(buf)
                    
                    # Quick parse to determine direction
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        
                        # Get IP layer
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                        elif isinstance(eth.data, dpkt.ip6.IP6):
                            ip = eth.data
                        else:
                            continue
                        
                        # Get transport layer
                        if isinstance(ip.data, dpkt.udp.UDP):
                            transport = ip.data
                            src_port = transport.sport
                            dst_port = transport.dport
                        elif isinstance(ip.data, dpkt.tcp.TCP):
                            transport = ip.data
                            src_port = transport.sport
                            dst_port = transport.dport
                        else:
                            continue
                        
                        # Determine direction (client port usually higher)
                        is_outbound = src_port > dst_port
                        
                        # Binary search for matching window
                        for window in query_windows:
                            if window['start'] <= timestamp <= window['end']:
                                if is_outbound:
                                    window['bytes_sent'] += packet_size
                                    window['packets_sent'] += 1
                                else:
                                    window['bytes_received'] += packet_size
                                    window['packets_received'] += 1
                                matched_count += 1
                                break
                            elif timestamp < window['start']:
                                break  # No more windows to check
                    
                    except Exception:
                        continue
                
                print(f"    ✓ Processed {packet_count} packets, matched {matched_count}")
                
                # Convert to DataFrame
                bandwidth_df = pd.DataFrame(query_windows)
                return bandwidth_df[['index', 'bytes_sent', 'bytes_received', 
                                   'packets_sent', 'packets_received']]
        
        except Exception as e:
            print(f"    ✗ Error reading pcap: {e}")
            return None
    
    def load_data(self):
        """Load all relevant CSV files and extract bandwidth from pcaps"""
        print("Loading data and analyzing bandwidth...")
        
        for provider_dir in self.results_dir.iterdir():
            if not provider_dir.is_dir():
                continue
            
            provider = provider_dir.name
            
            for csv_file in provider_dir.glob('*.csv'):
                if not self.should_include_file(csv_file):
                    continue
                
                try:
                    df = pd.read_csv(csv_file)
                    df['provider'] = provider
                    df['test_file'] = csv_file.stem
                    df['csv_path'] = str(csv_file)
                    
                    # Find corresponding pcap file
                    pcap_file = csv_file.with_suffix('.pcap')
                    if pcap_file.exists():
                        print(f"  Processing: {provider}/{csv_file.name}")
                        bandwidth_data = self.extract_bandwidth_from_pcap_fast(pcap_file, df)
                        
                        if bandwidth_data is not None and len(bandwidth_data) > 0:
                            # Merge bandwidth data
                            df = df.reset_index(drop=True)
                            for col in ['bytes_sent', 'bytes_received', 'packets_sent', 'packets_received']:
                                df[col] = 0
                            
                            for _, row in bandwidth_data.iterrows():
                                idx = int(row['index'])
                                if idx < len(df):
                                    df.at[idx, 'bytes_sent'] = row['bytes_sent']
                                    df.at[idx, 'bytes_received'] = row['bytes_received']
                                    df.at[idx, 'packets_sent'] = row['packets_sent']
                                    df.at[idx, 'packets_received'] = row['packets_received']
                            
                            df['total_bytes'] = df['bytes_sent'] + df['bytes_received']
                            
                            print(f"    ✓ Extracted bandwidth for {len(df)} queries")
                        else:
                            print(f"    ⚠ Could not extract bandwidth data")
                    else:
                        print(f"  ⚠ No pcap found for {csv_file.name}")
                    
                    self.all_data.append(df)
                    
                except Exception as e:
                    print(f"  ✗ Error loading {csv_file}: {e}")
                    import traceback
                    traceback.print_exc()
        
        print(f"\nTotal files loaded: {len(self.all_data)}")
    
    def create_line_graphs(self, output_dir='output/line_graphs'):
        """Create line graphs for latency and bandwidth"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        print("\nGenerating line graphs...")
        
        for df in self.all_data:
            provider = df['provider'].iloc[0]
            test_name = df['test_file'].iloc[0]
            
            df['query_index'] = range(1, len(df) + 1)
            
            # Create figure with 2 subplots
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
            
            # Plot 1: Latency
            ax1.plot(df['query_index'], df['duration_ms'], marker='o', 
                    markersize=4, linewidth=1, alpha=0.7, color='steelblue')
            mean_latency = df['duration_ms'].mean()
            ax1.axhline(y=mean_latency, color='r', linestyle='--', 
                       label=f'Mean: {mean_latency:.2f} ms', linewidth=2)
            ax1.set_xlabel('Query Number', fontsize=12)
            ax1.set_ylabel('Latency (ms)', fontsize=12)
            ax1.set_title('Latency Over Time', fontsize=12, fontweight='bold')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Plot 2: Bandwidth
            if 'total_bytes' in df.columns and df['total_bytes'].sum() > 0:
                ax2.plot(df['query_index'], df['bytes_sent'], marker='s', 
                        markersize=4, linewidth=1, alpha=0.7, 
                        color='orange', label='Sent')
                ax2.plot(df['query_index'], df['bytes_received'], marker='^', 
                        markersize=4, linewidth=1, alpha=0.7, 
                        color='green', label='Received')
                
                mean_sent = df['bytes_sent'].mean()
                mean_received = df['bytes_received'].mean()
                ax2.axhline(y=mean_sent, color='orange', linestyle='--', 
                           linewidth=1.5, alpha=0.5)
                ax2.axhline(y=mean_received, color='green', linestyle='--', 
                           linewidth=1.5, alpha=0.5)
                
                ax2.set_xlabel('Query Number', fontsize=12)
                ax2.set_ylabel('Bytes', fontsize=12)
                ax2.set_title(f'Bandwidth Over Time (Mean: ↑{mean_sent:.0f}B ↓{mean_received:.0f}B)', 
                             fontsize=12, fontweight='bold')
                ax2.legend()
                ax2.grid(True, alpha=0.3)
            
            fig.suptitle(f'{provider.upper()} - {test_name}', 
                        fontsize=14, fontweight='bold')
            plt.tight_layout()
            
            filename = f"{provider}_{test_name}.png"
            plt.savefig(f'{output_dir}/{filename}', bbox_inches='tight')
            plt.close()
            
            print(f"  ✓ Created: {filename}")
    
    def get_protocol_name(self, test_file):
        """Extract clean protocol name"""
        name = test_file.replace('-persist', '')
        
        protocol_map = {
            'udp': 'Plain DNS (UDP)',
            'tls': 'DoT (DNS over TLS)',
            'https': 'DoH (DNS over HTTPS)',
            'doh3': 'DoH/3 (DNS over HTTP/3)',
            'doq': 'DoQ (DNS over QUIC)'
        }
        
        return protocol_map.get(name, name.upper())
    
    def create_resolver_comparison_bars(self, output_dir='output/comparisons'):
        """Create bar graphs comparing resolvers for latency and bandwidth"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        print("\nGenerating resolver comparison graphs...")
        
        combined_df = pd.concat(self.all_data, ignore_index=True)
        protocols = combined_df['test_file'].unique()
        
        for protocol in protocols:
            protocol_data = combined_df[combined_df['test_file'] == protocol]
            protocol_name = self.get_protocol_name(protocol)
            
            # Latency stats
            latency_stats = protocol_data.groupby('provider')['duration_ms'].agg([
                ('mean', 'mean'),
                ('median', 'median'),
                ('std', 'std')
            ]).reset_index()
            
            # Create latency comparison
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
            fig.suptitle(f'{protocol_name} - Latency Comparison', 
                        fontsize=16, fontweight='bold')
            
            # Mean latency
            bars1 = ax1.bar(latency_stats['provider'], latency_stats['mean'], 
                           color='steelblue', alpha=0.8, edgecolor='black')
            ax1.errorbar(latency_stats['provider'], latency_stats['mean'], 
                        yerr=latency_stats['std'], fmt='none', color='black', 
                        capsize=5, alpha=0.6)
            
            for bar in bars1:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height:.2f}',
                        ha='center', va='bottom', fontweight='bold')
            
            ax1.set_xlabel('Resolver', fontsize=12)
            ax1.set_ylabel('Mean Latency (ms)', fontsize=12)
            ax1.set_title('Mean Latency', fontsize=12)
            ax1.grid(axis='y', alpha=0.3)
            
            # Median latency
            bars2 = ax2.bar(latency_stats['provider'], latency_stats['median'], 
                           color='coral', alpha=0.8, edgecolor='black')
            
            for bar in bars2:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height:.2f}',
                        ha='center', va='bottom', fontweight='bold')
            
            ax2.set_xlabel('Resolver', fontsize=12)
            ax2.set_ylabel('Median Latency (ms)', fontsize=12)
            ax2.set_title('Median Latency', fontsize=12)
            ax2.grid(axis='y', alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(f'{output_dir}/latency_{protocol}.png', bbox_inches='tight')
            plt.close()
            print(f"  ✓ Created: latency_{protocol}.png")
            
            # Bandwidth comparison
            if 'total_bytes' in protocol_data.columns and protocol_data['total_bytes'].sum() > 0:
                bandwidth_stats = protocol_data.groupby('provider').agg({
                    'bytes_sent': 'mean',
                    'bytes_received': 'mean',
                    'total_bytes': 'mean'
                }).reset_index()
                
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
                fig.suptitle(f'{protocol_name} - Bandwidth Comparison', 
                            fontsize=16, fontweight='bold')
                
                # Sent vs Received
                x = np.arange(len(bandwidth_stats))
                width = 0.35
                
                bars1 = ax1.bar(x - width/2, bandwidth_stats['bytes_sent'], width,
                               label='Sent', color='orange', alpha=0.8, edgecolor='black')
                bars2 = ax1.bar(x + width/2, bandwidth_stats['bytes_received'], width,
                               label='Received', color='green', alpha=0.8, edgecolor='black')
                
                ax1.set_xlabel('Resolver', fontsize=12)
                ax1.set_ylabel('Bytes per Query', fontsize=12)
                ax1.set_title('Average Bandwidth per Query', fontsize=12)
                ax1.set_xticks(x)
                ax1.set_xticklabels(bandwidth_stats['provider'])
                ax1.legend()
                ax1.grid(axis='y', alpha=0.3)
                
                # Total bandwidth
                bars3 = ax2.bar(bandwidth_stats['provider'], bandwidth_stats['total_bytes'],
                               color='purple', alpha=0.8, edgecolor='black')
                
                for bar in bars3:
                    height = bar.get_height()
                    ax2.text(bar.get_x() + bar.get_width()/2., height,
                            f'{height:.0f}',
                            ha='center', va='bottom', fontweight='bold')
                
                ax2.set_xlabel('Resolver', fontsize=12)
                ax2.set_ylabel('Total Bytes per Query', fontsize=12)
                ax2.set_title('Total Bandwidth per Query', fontsize=12)
                ax2.grid(axis='y', alpha=0.3)
                
                plt.tight_layout()
                plt.savefig(f'{output_dir}/bandwidth_{protocol}.png', bbox_inches='tight')
                plt.close()
                print(f"  ✓ Created: bandwidth_{protocol}.png")
    
    def generate_latex_tables(self, output_dir='output/tables'):
        """Generate LaTeX tables with latency and bandwidth statistics"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        print("\nGenerating LaTeX tables...")
        
        combined_df = pd.concat(self.all_data, ignore_index=True)
        
        # Generate latency table for each resolver
        for provider in combined_df['provider'].unique():
            provider_data = combined_df[combined_df['provider'] == provider]
            
            stats = provider_data.groupby('test_file')['duration_ms'].agg([
                ('Mean', 'mean'),
                ('Median', 'median'),
                ('Std Dev', 'std'),
                ('P95', lambda x: x.quantile(0.95)),
                ('P99', lambda x: x.quantile(0.99))
            ]).round(2)
            
            stats.index = stats.index.map(self.get_protocol_name)
            stats.index.name = 'Protocol'
            
            latex_code = stats.to_latex(
                caption=f'{provider.upper()} - Latency Statistics (ms)',
                label=f'tab:{provider}_latency',
                float_format="%.2f"
            )
            
            with open(f'{output_dir}/{provider}_latency.tex', 'w') as f:
                f.write(latex_code)
            
            print(f"  ✓ Created: {provider}_latency.tex")
        
        # Generate bandwidth table for each resolver
        for provider in combined_df['provider'].unique():
            provider_data = combined_df[combined_df['provider'] == provider]
            
            if 'total_bytes' not in provider_data.columns or provider_data['total_bytes'].sum() == 0:
                continue
            
            bandwidth_stats = provider_data.groupby('test_file').agg({
                'bytes_sent': 'mean',
                'bytes_received': 'mean',
                'total_bytes': 'mean'
            }).round(2)
            
            bandwidth_stats.columns = ['Avg Sent (B)', 'Avg Received (B)', 'Avg Total (B)']
            bandwidth_stats.index = bandwidth_stats.index.map(self.get_protocol_name)
            bandwidth_stats.index.name = 'Protocol'
            
            latex_code = bandwidth_stats.to_latex(
                caption=f'{provider.upper()} - Bandwidth Statistics',
                label=f'tab:{provider}_bandwidth',
                float_format="%.2f"
            )
            
            with open(f'{output_dir}/{provider}_bandwidth.tex', 'w') as f:
                f.write(latex_code)
            
            print(f"  ✓ Created: {provider}_bandwidth.tex")
        
        # Generate protocol efficiency table
        print("\nGenerating protocol efficiency table...")
        
        if 'total_bytes' in combined_df.columns and combined_df['total_bytes'].sum() > 0:
            protocol_bandwidth = combined_df.groupby('test_file').agg({
                'bytes_sent': 'mean',
                'bytes_received': 'mean',
                'total_bytes': 'mean'
            }).round(2)
            
            # Find UDP baseline
            udp_baseline = None
            for protocol in protocol_bandwidth.index:
                if 'udp' in protocol:
                    udp_baseline = protocol_bandwidth.loc[protocol, 'total_bytes']
                    break
            
            if udp_baseline and udp_baseline > 0:
                protocol_bandwidth['Overhead vs UDP (%)'] = (
                    (protocol_bandwidth['total_bytes'] - udp_baseline) / udp_baseline * 100
                ).round(1)
                protocol_bandwidth['Efficiency (%)'] = (
                    100 / (1 + protocol_bandwidth['Overhead vs UDP (%)'] / 100)
                ).round(1)
            
            protocol_bandwidth.columns = ['Avg Sent (B)', 'Avg Received (B)', 
                                         'Avg Total (B)', 'Overhead (%)', 'Efficiency (%)']
            protocol_bandwidth.index = protocol_bandwidth.index.map(self.get_protocol_name)
            protocol_bandwidth.index.name = 'Protocol'
            
            latex_code = protocol_bandwidth.to_latex(
                caption='Protocol Bandwidth Efficiency Comparison',
                label='tab:protocol_efficiency',
                float_format="%.2f"
            )
            
            with open(f'{output_dir}/protocol_efficiency.tex', 'w') as f:
                f.write(latex_code)
            
            print(f"  ✓ Created: protocol_efficiency.tex")
            print("\n--- Protocol Efficiency ---")
            print(protocol_bandwidth.to_string())
        
        # Generate combined comparison tables
        for metric in ['Mean', 'Median', 'P95']:
            comparison_stats = combined_df.groupby(['provider', 'test_file'])['duration_ms'].agg([
                ('Mean', 'mean'),
                ('Median', 'median'),
                ('P95', lambda x: x.quantile(0.95))
            ]).round(2)
            
            pivot_table = comparison_stats[metric].unstack(level=0)
            pivot_table.index = pivot_table.index.map(self.get_protocol_name)
            pivot_table.index.name = 'Protocol'
            
            latex_code = pivot_table.to_latex(
                caption=f'Resolver Latency Comparison - {metric} (ms)',
                label=f'tab:comparison_{metric.lower()}',
                float_format="%.2f"
            )
            
            with open(f'{output_dir}/comparison_{metric.lower()}.tex', 'w') as f:
                f.write(latex_code)
            
            print(f"  ✓ Created: comparison_{metric.lower()}.tex")
    
    def run_analysis(self):
        """Run the complete analysis"""
        print("="*80)
        print("Fast DNS QoS Analysis with Bandwidth")
        print("="*80)
        
        self.load_data()
        
        if not self.all_data:
            print("\n⚠ No data loaded.")
            return
        
        print("\n" + "="*80)
        self.create_line_graphs()
        
        print("\n" + "="*80)
        self.create_resolver_comparison_bars()
        
        print("\n" + "="*80)
        self.generate_latex_tables()
        
        print("\n" + "="*80)
        print("✓ Analysis Complete!")
        print("="*80)


if __name__ == "__main__":
    analyzer = FastDNSAnalyzer(results_dir='results')
    analyzer.run_analysis()

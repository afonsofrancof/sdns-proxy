import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from scipy import stats
import warnings

warnings.filterwarnings('ignore')

# Set style for publication-quality plots
sns.set_style("whitegrid")
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10
plt.rcParams['figure.figsize'] = (12, 6)

class DNSAnalyzer:
    def __init__(self, results_dir='results'):
        self.results_dir = Path(results_dir)
        self.df = None
        
    def load_all_data(self):
        """Load all CSV files from the results directory"""
        data_frames = []
        
        providers = ['adguard', 'cloudflare', 'google', 'quad9']
        
        for provider in providers:
            provider_path = self.results_dir / provider
            if not provider_path.exists():
                continue
                
            for csv_file in provider_path.glob('*.csv'):
                try:
                    df = pd.read_csv(csv_file)
                    df['provider'] = provider
                    df['test_config'] = csv_file.stem
                    data_frames.append(df)
                except Exception as e:
                    print(f"Error loading {csv_file}: {e}")
        
        self.df = pd.concat(data_frames, ignore_index=True)
        self._clean_and_enrich_data()
        print(f"Loaded {len(self.df)} DNS queries across {len(data_frames)} test configurations")
        
    def _clean_and_enrich_data(self):
        """Clean data and add useful columns"""
        # Remove failed queries
        self.df = self.df[self.df['error'].isna()]
        
        # Extract protocol base (remove -auth, -trust suffixes)
        self.df['protocol_base'] = self.df['protocol'].str.replace('-auth|-trust', '', regex=True)
        
        # DNSSEC configuration
        self.df['dnssec_mode'] = 'none'
        self.df.loc[self.df['auth_dnssec'] == True, 'dnssec_mode'] = 'auth'
        self.df.loc[(self.df['dnssec'] == True) & (self.df['auth_dnssec'] == False), 'dnssec_mode'] = 'trust'
        
        # Protocol categories
        self.df['protocol_category'] = self.df['protocol_base'].map({
            'udp': 'Plain DNS',
            'tls': 'DoT',
            'https': 'DoH',
            'doh3': 'DoH/3',
            'doq': 'DoQ'
        })
        
        # Connection persistence
        self.df['persistence'] = self.df['keep_alive'].fillna(False)
        
    def generate_summary_statistics(self):
        """Generate comprehensive summary statistics"""
        print("\n" + "="*80)
        print("SUMMARY STATISTICS")
        print("="*80)
        
        # Overall statistics
        print("\n--- Overall Performance ---")
        print(f"Total queries: {len(self.df)}")
        print(f"Mean latency: {self.df['duration_ms'].mean():.2f} ms")
        print(f"Median latency: {self.df['duration_ms'].median():.2f} ms")
        print(f"95th percentile: {self.df['duration_ms'].quantile(0.95):.2f} ms")
        print(f"99th percentile: {self.df['duration_ms'].quantile(0.99):.2f} ms")
        
        # By protocol
        print("\n--- Performance by Protocol ---")
        protocol_stats = self.df.groupby('protocol_category')['duration_ms'].agg([
            ('count', 'count'),
            ('mean', 'mean'),
            ('median', 'median'),
            ('std', 'std'),
            ('p95', lambda x: x.quantile(0.95)),
            ('p99', lambda x: x.quantile(0.99))
        ]).round(2)
        print(protocol_stats)
        
        # By provider
        print("\n--- Performance by Provider ---")
        provider_stats = self.df.groupby('provider')['duration_ms'].agg([
            ('count', 'count'),
            ('mean', 'mean'),
            ('median', 'median'),
            ('std', 'std'),
            ('p95', lambda x: x.quantile(0.95))
        ]).round(2)
        print(provider_stats)
        
        # DNSSEC impact
        print("\n--- DNSSEC Validation Impact ---")
        dnssec_stats = self.df.groupby('dnssec_mode')['duration_ms'].agg([
            ('count', 'count'),
            ('mean', 'mean'),
            ('median', 'median'),
            ('overhead_vs_none', lambda x: x.mean())
        ]).round(2)
        
        # Calculate overhead percentage
        baseline = dnssec_stats.loc['none', 'mean'] if 'none' in dnssec_stats.index else 0
        if baseline > 0:
            dnssec_stats['overhead_pct'] = ((dnssec_stats['overhead_vs_none'] - baseline) / baseline * 100).round(1)
        print(dnssec_stats)
        
        # Bandwidth analysis
        print("\n--- Bandwidth Usage ---")
        bandwidth_stats = self.df.groupby('protocol_category').agg({
            'request_size_bytes': ['mean', 'median'],
            'response_size_bytes': ['mean', 'median']
        }).round(2)
        print(bandwidth_stats)
        
        # Persistence impact (where applicable)
        print("\n--- Connection Persistence Impact ---")
        persist_protocols = self.df[self.df['protocol_base'].isin(['tls', 'https'])]
        if len(persist_protocols) > 0:
            persist_stats = persist_protocols.groupby(['protocol_base', 'persistence'])['duration_ms'].agg([
                ('mean', 'mean'),
                ('median', 'median')
            ]).round(2)
            print(persist_stats)
        
        return {
            'protocol': protocol_stats,
            'provider': provider_stats,
            'dnssec': dnssec_stats,
            'bandwidth': bandwidth_stats
        }
    
    def plot_latency_by_protocol(self, output_dir='plots'):
        """Violin plot of latency distribution by protocol"""
        Path(output_dir).mkdir(exist_ok=True)
        
        plt.figure(figsize=(14, 7))
        
        # Order protocols logically
        protocol_order = ['Plain DNS', 'DoT', 'DoH', 'DoH/3', 'DoQ']
        available_protocols = [p for p in protocol_order if p in self.df['protocol_category'].values]
        
        sns.violinplot(data=self.df, x='protocol_category', y='duration_ms', 
                      order=available_protocols, inner='box', cut=0)
        
        plt.title('DNS Query Latency Distribution by Protocol', fontsize=14, fontweight='bold')
        plt.xlabel('Protocol', fontsize=12)
        plt.ylabel('Response Time (ms)', fontsize=12)
        plt.xticks(rotation=0)
        
        # Add mean values as annotations
        for i, protocol in enumerate(available_protocols):
            mean_val = self.df[self.df['protocol_category'] == protocol]['duration_ms'].mean()
            plt.text(i, mean_val, f'{mean_val:.1f}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/latency_by_protocol.png', bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: latency_by_protocol.png")
    
    def plot_provider_comparison(self, output_dir='plots'):
        """Box plot comparing providers across protocols"""
        Path(output_dir).mkdir(exist_ok=True)
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Provider Performance Comparison by Protocol', fontsize=16, fontweight='bold')
        
        protocols = self.df['protocol_category'].unique()
        protocols = [p for p in ['Plain DNS', 'DoT', 'DoH', 'DoH/3'] if p in protocols]
        
        for idx, protocol in enumerate(protocols[:4]):
            ax = axes[idx // 2, idx % 2]
            data = self.df[self.df['protocol_category'] == protocol]
            
            if len(data) > 0:
                sns.boxplot(data=data, x='provider', y='duration_ms', ax=ax)
                ax.set_title(f'{protocol}', fontsize=12, fontweight='bold')
                ax.set_xlabel('Provider', fontsize=10)
                ax.set_ylabel('Response Time (ms)', fontsize=10)
                ax.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/provider_comparison.png', bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: provider_comparison.png")
    
    def plot_dnssec_impact(self, output_dir='plots'):
        """Compare DNSSEC validation methods (trust vs auth)"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Filter for protocols that have DNSSEC variations
        dnssec_data = self.df[self.df['dnssec_mode'] != 'none'].copy()
        
        if len(dnssec_data) == 0:
            print("⚠ No DNSSEC data available")
            return
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        # Plot 1: Overall DNSSEC impact
        protocol_order = ['Plain DNS', 'DoT', 'DoH', 'DoH/3', 'DoQ']
        available = [p for p in protocol_order if p in self.df['protocol_category'].values]
        
        sns.barplot(data=self.df, x='protocol_category', y='duration_ms', 
                   hue='dnssec_mode', order=available, ax=ax1, ci=95)
        ax1.set_title('DNSSEC Validation Overhead by Protocol', fontsize=12, fontweight='bold')
        ax1.set_xlabel('Protocol', fontsize=10)
        ax1.set_ylabel('Mean Response Time (ms)', fontsize=10)
        ax1.legend(title='DNSSEC Mode', labels=['No DNSSEC', 'Auth (Full)', 'Trust (Resolver)'])
        ax1.tick_params(axis='x', rotation=0)
        
        # Plot 2: Trust vs Auth comparison
        comparison_data = dnssec_data.groupby(['protocol_category', 'dnssec_mode'])['duration_ms'].mean().reset_index()
        pivot_data = comparison_data.pivot(index='protocol_category', columns='dnssec_mode', values='duration_ms')
        
        if 'auth' in pivot_data.columns and 'trust' in pivot_data.columns:
            pivot_data['overhead_pct'] = ((pivot_data['auth'] - pivot_data['trust']) / pivot_data['trust'] * 100)
            pivot_data['overhead_pct'].plot(kind='bar', ax=ax2, color='coral')
            ax2.set_title('Auth vs Trust: Additional Overhead (%)', fontsize=12, fontweight='bold')
            ax2.set_xlabel('Protocol', fontsize=10)
            ax2.set_ylabel('Additional Overhead (%)', fontsize=10)
            ax2.axhline(y=0, color='black', linestyle='--', linewidth=0.8)
            ax2.tick_params(axis='x', rotation=45)
            ax2.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/dnssec_impact.png', bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: dnssec_impact.png")
    
    def plot_persistence_impact(self, output_dir='plots'):
        """Analyze impact of connection persistence"""
        Path(output_dir).mkdir(exist_ok=True)
        
        persist_data = self.df[self.df['protocol_base'].isin(['tls', 'https'])].copy()
        
        if len(persist_data) == 0:
            print("⚠ No persistence data available")
            return
        
        plt.figure(figsize=(12, 6))
        
        sns.barplot(data=persist_data, x='protocol_base', y='duration_ms', 
                   hue='persistence', ci=95)
        
        plt.title('Impact of Connection Persistence on Latency', fontsize=14, fontweight='bold')
        plt.xlabel('Protocol', fontsize=12)
        plt.ylabel('Mean Response Time (ms)', fontsize=12)
        plt.legend(title='Keep-Alive', labels=['Disabled', 'Enabled'])
        
        # Calculate and annotate overhead reduction
        for protocol in persist_data['protocol_base'].unique():
            protocol_data = persist_data[persist_data['protocol_base'] == protocol]
            
            no_persist = protocol_data[protocol_data['persistence'] == False]['duration_ms'].mean()
            with_persist = protocol_data[protocol_data['persistence'] == True]['duration_ms'].mean()
            
            if not np.isnan(no_persist) and not np.isnan(with_persist):
                reduction = ((no_persist - with_persist) / no_persist * 100)
                print(f"{protocol}: {reduction:.1f}% reduction with persistence")
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/persistence_impact.png', bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: persistence_impact.png")
    
    def plot_bandwidth_overhead(self, output_dir='plots'):
        """Visualize bandwidth usage by protocol"""
        Path(output_dir).mkdir(exist_ok=True)
        
        bandwidth_data = self.df.groupby('protocol_category').agg({
            'request_size_bytes': 'mean',
            'response_size_bytes': 'mean'
        }).reset_index()
        
        bandwidth_data['total_bytes'] = (bandwidth_data['request_size_bytes'] + 
                                         bandwidth_data['response_size_bytes'])
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        # Plot 1: Request vs Response sizes
        x = np.arange(len(bandwidth_data))
        width = 0.35
        
        ax1.bar(x - width/2, bandwidth_data['request_size_bytes'], width, 
               label='Request', alpha=0.8)
        ax1.bar(x + width/2, bandwidth_data['response_size_bytes'], width, 
               label='Response', alpha=0.8)
        
        ax1.set_xlabel('Protocol', fontsize=12)
        ax1.set_ylabel('Bytes', fontsize=12)
        ax1.set_title('Average Request/Response Sizes', fontsize=12, fontweight='bold')
        ax1.set_xticks(x)
        ax1.set_xticklabels(bandwidth_data['protocol_category'])
        ax1.legend()
        ax1.grid(axis='y', alpha=0.3)
        
        # Plot 2: Total bandwidth overhead vs UDP baseline
        udp_total = bandwidth_data[bandwidth_data['protocol_category'] == 'Plain DNS']['total_bytes'].values
        if len(udp_total) > 0:
            bandwidth_data['overhead_vs_udp'] = ((bandwidth_data['total_bytes'] - udp_total[0]) / udp_total[0] * 100)
            
            colors = ['green' if x < 0 else 'red' for x in bandwidth_data['overhead_vs_udp']]
            ax2.bar(bandwidth_data['protocol_category'], bandwidth_data['overhead_vs_udp'], 
                   color=colors, alpha=0.7)
            ax2.axhline(y=0, color='black', linestyle='--', linewidth=0.8)
            ax2.set_xlabel('Protocol', fontsize=12)
            ax2.set_ylabel('Overhead vs Plain DNS (%)', fontsize=12)
            ax2.set_title('Bandwidth Overhead', fontsize=12, fontweight='bold')
            ax2.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/bandwidth_overhead.png', bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: bandwidth_overhead.png")
    
    def plot_heatmap(self, output_dir='plots'):
        """Heatmap of provider-protocol performance"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Create pivot table
        heatmap_data = self.df.groupby(['provider', 'protocol_category'])['duration_ms'].median().unstack()
        
        plt.figure(figsize=(12, 8))
        sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='RdYlGn_r', 
                   cbar_kws={'label': 'Median Latency (ms)'})
        
        plt.title('DNS Provider-Protocol Performance Matrix', fontsize=14, fontweight='bold')
        plt.xlabel('Protocol', fontsize=12)
        plt.ylabel('Provider', fontsize=12)
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/provider_protocol_heatmap.png', bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: provider_protocol_heatmap.png")
    
    def plot_percentile_comparison(self, output_dir='plots'):
        """Plot percentile comparison across protocols"""
        Path(output_dir).mkdir(exist_ok=True)
        
        percentiles = [50, 75, 90, 95, 99]
        protocol_order = ['Plain DNS', 'DoT', 'DoH', 'DoH/3', 'DoQ']
        available = [p for p in protocol_order if p in self.df['protocol_category'].values]
        
        percentile_data = []
        for protocol in available:
            data = self.df[self.df['protocol_category'] == protocol]['duration_ms']
            for p in percentiles:
                percentile_data.append({
                    'protocol': protocol,
                    'percentile': f'P{p}',
                    'latency': np.percentile(data, p)
                })
        
        percentile_df = pd.DataFrame(percentile_data)
        
        plt.figure(figsize=(14, 7))
        sns.barplot(data=percentile_df, x='protocol', y='latency', hue='percentile', order=available)
        
        plt.title('Latency Percentiles by Protocol', fontsize=14, fontweight='bold')
        plt.xlabel('Protocol', fontsize=12)
        plt.ylabel('Response Time (ms)', fontsize=12)
        plt.legend(title='Percentile', bbox_to_anchor=(1.05, 1), loc='upper left')
        
        plt.tight_layout()
        plt.savefig(f'{output_dir}/percentile_comparison.png', bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: percentile_comparison.png")
    
    def statistical_tests(self):
        """Perform statistical significance tests"""
        print("\n" + "="*80)
        print("STATISTICAL TESTS")
        print("="*80)
        
        # Test 1: Protocol differences (Kruskal-Wallis)
        protocols = self.df['protocol_category'].unique()
        if len(protocols) > 2:
            groups = [self.df[self.df['protocol_category'] == p]['duration_ms'].values 
                     for p in protocols]
            h_stat, p_value = stats.kruskal(*groups)
            print(f"\n--- Kruskal-Wallis Test (Protocol Differences) ---")
            print(f"H-statistic: {h_stat:.4f}")
            print(f"p-value: {p_value:.4e}")
            print(f"Result: {'Significant' if p_value < 0.05 else 'Not significant'} differences between protocols")
        
        # Test 2: DNSSEC impact (Mann-Whitney U)
        if 'none' in self.df['dnssec_mode'].values and 'auth' in self.df['dnssec_mode'].values:
            none_data = self.df[self.df['dnssec_mode'] == 'none']['duration_ms']
            auth_data = self.df[self.df['dnssec_mode'] == 'auth']['duration_ms']
            
            u_stat, p_value = stats.mannwhitneyu(none_data, auth_data, alternative='two-sided')
            print(f"\n--- Mann-Whitney U Test (No DNSSEC vs Auth) ---")
            print(f"U-statistic: {u_stat:.4f}")
            print(f"p-value: {p_value:.4e}")
            print(f"Result: {'Significant' if p_value < 0.05 else 'Not significant'} difference")
        
        # Test 3: Trust vs Auth comparison
        if 'trust' in self.df['dnssec_mode'].values and 'auth' in self.df['dnssec_mode'].values:
            trust_data = self.df[self.df['dnssec_mode'] == 'trust']['duration_ms']
            auth_data = self.df[self.df['dnssec_mode'] == 'auth']['duration_ms']
            
            u_stat, p_value = stats.mannwhitneyu(trust_data, auth_data, alternative='two-sided')
            print(f"\n--- Mann-Whitney U Test (Trust vs Auth) ---")
            print(f"U-statistic: {u_stat:.4f}")
            print(f"p-value: {p_value:.4e}")
            print(f"Result: Auth is {'significantly' if p_value < 0.05 else 'not significantly'} slower than Trust")
    
    def generate_latex_table(self, output_dir='plots'):
        """Generate LaTeX table for thesis"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Summary table by protocol
        summary = self.df.groupby('protocol_category')['duration_ms'].agg([
            ('Mean', 'mean'),
            ('Median', 'median'),
            ('Std Dev', 'std'),
            ('P95', lambda x: x.quantile(0.95)),
            ('P99', lambda x: x.quantile(0.99))
        ]).round(2)
        
        latex_code = summary.to_latex(float_format="%.2f")
        
        with open(f'{output_dir}/summary_table.tex', 'w') as f:
            f.write(latex_code)
        
        print(f"✓ Saved: summary_table.tex")
        print("\nLaTeX Table Preview:")
        print(latex_code)
    
    def run_full_analysis(self):
        """Run complete analysis pipeline"""
        print("="*80)
        print("DNS QoS Analysis - Starting Full Analysis")
        print("="*80)
        
        # Load data
        print("\n[1/10] Loading data...")
        self.load_all_data()
        
        # Generate statistics
        print("\n[2/10] Generating summary statistics...")
        self.generate_summary_statistics()
        
        # Statistical tests
        print("\n[3/10] Running statistical tests...")
        self.statistical_tests()
        
        # Generate plots
        print("\n[4/10] Creating latency by protocol plot...")
        self.plot_latency_by_protocol()
        
        print("\n[5/10] Creating provider comparison plot...")
        self.plot_provider_comparison()
        
        print("\n[6/10] Creating DNSSEC impact plot...")
        self.plot_dnssec_impact()
        
        print("\n[7/10] Creating persistence impact plot...")
        self.plot_persistence_impact()
        
        print("\n[8/10] Creating bandwidth overhead plot...")
        self.plot_bandwidth_overhead()
        
        print("\n[9/10] Creating heatmap...")
        self.plot_heatmap()
        
        print("\n[10/10] Creating percentile comparison...")
        self.plot_percentile_comparison()
        
        # Generate LaTeX table
        print("\n[Bonus] Generating LaTeX table...")
        self.generate_latex_table()
        
        print("\n" + "="*80)
        print("✓ Analysis Complete! Check the 'plots' directory for all visualizations.")
        print("="*80)


if __name__ == "__main__":
    analyzer = DNSAnalyzer(results_dir='results')
    analyzer.run_full_analysis()

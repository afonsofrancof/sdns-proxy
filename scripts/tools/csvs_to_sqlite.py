#!/usr/bin/env python3
"""
Convert DNS CSV files to SQLite database.
Creates a single normalized table with unified DNSSEC handling.
"""

import sqlite3
import csv
from pathlib import Path
from dateutil import parser as date_parser


def create_database_schema(conn: sqlite3.Connection):
    """Create the database schema with indexes."""
    cursor = conn.cursor()
    
    # Main queries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            
            -- Metadata
            provider TEXT NOT NULL,
            protocol TEXT NOT NULL,
            dnssec_mode TEXT NOT NULL CHECK(dnssec_mode IN ('off', 'auth', 'trust')),
            
            -- Query details
            domain TEXT NOT NULL,
            query_type TEXT NOT NULL,
            keep_alive BOOLEAN NOT NULL,
            dns_server TEXT NOT NULL,
            
            -- Timing
            timestamp TEXT NOT NULL,
            timestamp_unix REAL NOT NULL,
            duration_ns INTEGER NOT NULL,
            duration_ms REAL NOT NULL,
            
            -- Size metrics
            request_size_bytes INTEGER,
            response_size_bytes INTEGER,
            
            -- Network metrics (from PCAP)
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            packets_sent INTEGER DEFAULT 0,
            packets_received INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            
            -- Response
            response_code TEXT,
            error TEXT
        )
    """)
    
    # Create indexes for common queries
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_provider 
        ON dns_queries(provider)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_protocol 
        ON dns_queries(protocol)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_dnssec_mode 
        ON dns_queries(dnssec_mode)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_keep_alive 
        ON dns_queries(keep_alive)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_provider_protocol_dnssec 
        ON dns_queries(provider, protocol, dnssec_mode)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp 
        ON dns_queries(timestamp_unix)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_domain 
        ON dns_queries(domain)
    """)
    
    conn.commit()


def parse_protocol_and_dnssec(filename: str) -> tuple[str, str, bool]:
    """
    Extract base protocol, DNSSEC mode, and keep_alive from filename.
    Returns (base_protocol, dnssec_mode, keep_alive)
    
    Examples:
        'udp.csv' -> ('udp', 'off', False)
        'udp-auth.csv' -> ('udp', 'auth', False)
        'tls.csv' -> ('tls', 'off', False)
        'tls-persist.csv' -> ('tls', 'off', True)
        'https-persist.csv' -> ('https', 'off', True)
        'https-auth-persist.csv' -> ('https', 'auth', True)
        'https-trust-persist.csv' -> ('https', 'trust', True)
        'doh3-auth.csv' -> ('doh3', 'auth', False)
        'doq.csv' -> ('doq', 'off', False)
    """
    name = filename.replace('.csv', '')
    
    # Check for persist suffix (keep_alive)
    keep_alive = False
    if name.endswith('-persist'):
        keep_alive = True
        name = name.replace('-persist', '')
    
    # Check for DNSSEC suffix
    dnssec_mode = 'off'
    if name.endswith('-auth'):
        dnssec_mode = 'auth'
        name = name.replace('-auth', '')
    elif name.endswith('-trust'):
        dnssec_mode = 'trust'
        name = name.replace('-trust', '')
    
    # For UDP, DoH3, and DoQ, keep_alive doesn't apply (connectionless)
    if name in ['udp', 'doh3', 'doq']:
        keep_alive = False
    
    return (name, dnssec_mode, keep_alive)


def str_to_bool(value: str) -> bool:
    """Convert string boolean to Python bool."""
    return value.lower() in ('true', '1', 'yes')


def import_csv_to_db(
    csv_path: Path,
    provider: str,
    conn: sqlite3.Connection
) -> int:
    """Import a CSV file into the database."""
    protocol, dnssec_mode, keep_alive_from_filename = parse_protocol_and_dnssec(csv_path.name)
    
    cursor = conn.cursor()
    rows_imported = 0
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            try:
                # Parse timestamp to Unix epoch
                dt = date_parser.isoparse(row['timestamp'])
                timestamp_unix = dt.timestamp()
                
                # Use keep_alive from filename (more reliable than CSV)
                keep_alive = keep_alive_from_filename
                
                # Handle optional fields (may not exist in older CSVs)
                bytes_sent = int(row.get('bytes_sent', 0) or 0)
                bytes_received = int(row.get('bytes_received', 0) or 0)
                packets_sent = int(row.get('packets_sent', 0) or 0)
                packets_received = int(row.get('packets_received', 0) or 0)
                total_bytes = int(row.get('total_bytes', 0) or 0)
                
                cursor.execute("""
                    INSERT INTO dns_queries (
                        provider, protocol, dnssec_mode,
                        domain, query_type, keep_alive,
                        dns_server, timestamp, timestamp_unix,
                        duration_ns, duration_ms,
                        request_size_bytes, response_size_bytes,
                        bytes_sent, bytes_received, packets_sent, packets_received, total_bytes,
                        response_code, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    provider,
                    protocol,
                    dnssec_mode,
                    row['domain'],
                    row['query_type'],
                    keep_alive,
                    row['dns_server'],
                    row['timestamp'],
                    timestamp_unix,
                    int(row['duration_ns']),
                    float(row['duration_ms']),
                    int(row.get('request_size_bytes') or 0),
                    int(row.get('response_size_bytes') or 0),
                    bytes_sent,
                    bytes_received,
                    packets_sent,
                    packets_received,
                    total_bytes,
                    row.get('response_code', ''),
                    row.get('error', '')
                ))
                
                rows_imported += 1
                
            except Exception as e:
                print(f"      Warning: Skipping row - {e}")
                continue
    
    conn.commit()
    return rows_imported


def main():
    """Main import pipeline."""
    print("\n" + "="*60)
    print("CSV to SQLite Database Converter")
    print("="*60)
    
    results_dir = Path('results')
    db_path = Path('dns.db')
    
    if not results_dir.exists():
        print(f"\n❌ Error: '{results_dir}' directory not found")
        return
    
    # Remove existing database
    if db_path.exists():
        print(f"\n⚠ Removing existing database: {db_path}")
        db_path.unlink()
    
    # Create database and schema
    print(f"\n📊 Creating database: {db_path}")
    conn = sqlite3.connect(db_path)
    create_database_schema(conn)
    print("✓ Schema created")
    
    # Import CSVs
    providers = ['adguard', 'cloudflare', 'google', 'quad9']
    total_rows = 0
    total_files = 0
    
    for provider in providers:
        provider_path = results_dir / provider
        
        if not provider_path.exists():
            print(f"\n⚠ Skipping {provider} - directory not found")
            continue
        
        print(f"\n{'='*60}")
        print(f"Importing: {provider.upper()}")
        print(f"{'='*60}")
        
        csv_files = sorted(provider_path.glob('*.csv'))
        provider_rows = 0
        provider_files = 0
        
        for csv_path in csv_files:
            # Skip backup files
            if '.bak' in csv_path.name:
                continue
            
            protocol, dnssec, keep_alive = parse_protocol_and_dnssec(csv_path.name)
            ka_str = "persistent" if keep_alive else "non-persist"
            print(f"  📄 {csv_path.name:30} → {protocol:8} (DNSSEC: {dnssec:5}, {ka_str})")
            
            rows = import_csv_to_db(csv_path, provider, conn)
            print(f"     ✓ Imported {rows:,} rows")
            
            provider_rows += rows
            provider_files += 1
        
        print(f"\n  Total: {provider_files} files, {provider_rows:,} rows")
        total_rows += provider_rows
        total_files += provider_files
    
    # Create summary
    print(f"\n{'='*60}")
    print("Database Summary")
    print(f"{'='*60}")
    
    cursor = conn.cursor()
    
    # Total counts
    cursor.execute("SELECT COUNT(*) FROM dns_queries")
    total_queries = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT provider) FROM dns_queries")
    unique_providers = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT protocol) FROM dns_queries")
    unique_protocols = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT domain) FROM dns_queries")
    unique_domains = cursor.fetchone()[0]
    
    print(f"\nTotal queries:     {total_queries:,}")
    print(f"Providers:         {unique_providers}")
    print(f"Protocols:         {unique_protocols}")
    print(f"Unique domains:    {unique_domains}")
    
    # Show breakdown by provider, protocol, DNSSEC, and keep_alive
    print(f"\nBreakdown by Provider, Protocol, DNSSEC & Keep-Alive:")
    print(f"{'-'*80}")
    
    cursor.execute("""
        SELECT provider, protocol, dnssec_mode, keep_alive, COUNT(*) as count
        FROM dns_queries
        GROUP BY provider, protocol, dnssec_mode, keep_alive
        ORDER BY provider, protocol, dnssec_mode, keep_alive
    """)
    
    current_provider = None
    for provider, protocol, dnssec, keep_alive, count in cursor.fetchall():
        if current_provider != provider:
            if current_provider is not None:
                print()
            current_provider = provider
        
        ka_str = "✓" if keep_alive else "✗"
        print(f"  {provider:12} | {protocol:8} | {dnssec:5} | KA:{ka_str} | {count:6,} queries")
    
    # Protocol distribution
    print(f"\n{'-'*80}")
    print("Protocol Distribution:")
    print(f"{'-'*80}")
    
    cursor.execute("""
        SELECT protocol, COUNT(*) as count
        FROM dns_queries
        GROUP BY protocol
        ORDER BY protocol
    """)
    
    for protocol, count in cursor.fetchall():
        pct = (count / total_queries) * 100
        print(f"  {protocol:8} | {count:8,} queries ({pct:5.1f}%)")
    
    # DNSSEC mode distribution
    print(f"\n{'-'*80}")
    print("DNSSEC Mode Distribution:")
    print(f"{'-'*80}")
    
    cursor.execute("""
        SELECT dnssec_mode, COUNT(*) as count
        FROM dns_queries
        GROUP BY dnssec_mode
        ORDER BY dnssec_mode
    """)
    
    for dnssec_mode, count in cursor.fetchall():
        pct = (count / total_queries) * 100
        print(f"  {dnssec_mode:5} | {count:8,} queries ({pct:5.1f}%)")
    
    # Keep-Alive distribution
    print(f"\n{'-'*80}")
    print("Keep-Alive Distribution:")
    print(f"{'-'*80}")
    
    cursor.execute("""
        SELECT keep_alive, COUNT(*) as count
        FROM dns_queries
        GROUP BY keep_alive
    """)
    
    for keep_alive, count in cursor.fetchall():
        ka_label = "Persistent" if keep_alive else "Non-persistent"
        pct = (count / total_queries) * 100
        print(f"  {ka_label:15} | {count:8,} queries ({pct:5.1f}%)")
    
    conn.close()
    
    print(f"\n{'='*60}")
    print(f"✓ Database created successfully: {db_path}")
    print(f"  Total: {total_files} files, {total_rows:,} rows")
    print(f"{'='*60}\n")
    
    # Print usage examples
    print("\n📖 Usage Examples for Metabase:")
    print(f"{'-'*60}")
    
    print("\n1. Compare protocols (DNSSEC off, persistent only):")
    print("""   SELECT provider, protocol, 
          AVG(duration_ms) as avg_latency,
          AVG(total_bytes) as avg_bytes
      FROM dns_queries
      WHERE dnssec_mode = 'off' AND keep_alive = 1
      GROUP BY provider, protocol;""")
    
    print("\n2. DNSSEC impact on UDP:")
    print("""   SELECT provider, dnssec_mode,
          AVG(duration_ms) as avg_latency
      FROM dns_queries
      WHERE protocol = 'udp'
      GROUP BY provider, dnssec_mode;""")
    
    print("\n3. Keep-alive impact on TLS:")
    print("""   SELECT provider, keep_alive,
          AVG(duration_ms) as avg_latency,
          AVG(total_bytes) as avg_bytes
      FROM dns_queries
      WHERE protocol = 'tls' AND dnssec_mode = 'off'
      GROUP BY provider, keep_alive;""")
    
    print("\n4. Time series for line graphs:")
    print("""   SELECT timestamp_unix, duration_ms, total_bytes
      FROM dns_queries
      WHERE provider = 'cloudflare' 
        AND protocol = 'https'
        AND dnssec_mode = 'off'
        AND keep_alive = 1
      ORDER BY timestamp_unix;""")
    
    print("\n5. Overall comparison table:")
    print("""   SELECT protocol, dnssec_mode, keep_alive,
          COUNT(*) as queries,
          AVG(duration_ms) as avg_latency,
          AVG(total_bytes) as avg_bytes
      FROM dns_queries
      GROUP BY protocol, dnssec_mode, keep_alive
      ORDER BY protocol, dnssec_mode, keep_alive;""")
    
    print(f"\n{'-'*60}\n")


if __name__ == '__main__':
    main()

#!/bin/bash

TOOL_PATH="$1"/"qol"
DOMAINS_FILE="$1"/"domains.txt"
OUTPUT_DIR="$1"/"results"

# Connection-based protocols that benefit from keep-alive (TCP-based)
CONN_SERVERS=(
    -s "tls://8.8.8.8:853"
    -s "tls://1.1.1.1:853"
    -s "tls://9.9.9.9:853"
    -s "tls://dns.adguard-dns.com:853"
    -s "https://dns.google/dns-query"
    -s "https://cloudflare-dns.com/dns-query"
    -s "https://dns10.quad9.net/dns-query"
    -s "https://dns.adguard-dns.com/dns-query"
)

# QUIC-based protocols (have built-in 0-RTT, keep-alive doesn't add value)
QUIC_SERVERS=(
    -s "doh3://dns.google/dns-query"
    -s "doh3://cloudflare-dns.com/dns-query"
    -s "doh3://dns.adguard-dns.com/dns-query"
    -s "doq://dns.adguard-dns.com:853"
)

# Connectionless protocols (no keep-alive)
CONNLESS_SERVERS=(
    -s "udp://8.8.8.8:53"
    -s "udp://1.1.1.1:53"
    -s "udp://9.9.9.9:53"
    -s "udp://dns.adguard-dns.com:53"
)

# Common args
COMMON_ARGS=(
    "$DOMAINS_FILE"
    --interface veth0
    --timeout 5s
)

# Combinations for TCP-based connection protocols
CONN_COMBINATIONS=(
    # DNSSEC off, Keep off
    ""
    
    # DNSSEC off, Keep on
    "--keep-alive"
    
    # DNSSEC on (trust), Keep on
    "--dnssec --keep-alive"
    
    # DNSSEC on (auth), Keep on
    "--dnssec --authoritative-dnssec --keep-alive"
)

# Combinations for QUIC and connectionless protocols (no keep-alive)
NO_KEEPALIVE_COMBINATIONS=(
    # DNSSEC off
    ""
    
    # DNSSEC on (trust)
    "--dnssec"
    
    # DNSSEC on (auth)
    "--dnssec --authoritative-dnssec"
)

echo "=== Running TCP-based protocols (TLS/HTTPS) ==="
for FLAGS in "${CONN_COMBINATIONS[@]}"; do
    echo "Running: $FLAGS"
    
    FLAGS_ARRAY=($FLAGS)
    
    sudo "$TOOL_PATH" run \
        --output-dir "$OUTPUT_DIR" \
        "${COMMON_ARGS[@]}" \
        "${CONN_SERVERS[@]}" \
        "${FLAGS_ARRAY[@]}"
    
    sleep 1
done

echo ""
echo "=== Running QUIC-based protocols (DoH3/DoQ) ==="
for FLAGS in "${NO_KEEPALIVE_COMBINATIONS[@]}"; do
    echo "Running: $FLAGS"
    
    FLAGS_ARRAY=($FLAGS)
    
    sudo "$TOOL_PATH" run \
        --output-dir "$OUTPUT_DIR" \
        "${COMMON_ARGS[@]}" \
        "${QUIC_SERVERS[@]}" \
        "${FLAGS_ARRAY[@]}"
    
    sleep 1
done

echo ""
echo "=== Running connectionless protocols (UDP) ==="
for FLAGS in "${NO_KEEPALIVE_COMBINATIONS[@]}"; do
    echo "Running: $FLAGS"
    
    FLAGS_ARRAY=($FLAGS)
    
    sudo "$TOOL_PATH" run \
        --output-dir "$OUTPUT_DIR" \
        "${COMMON_ARGS[@]}" \
        "${CONNLESS_SERVERS[@]}" \
        "${FLAGS_ARRAY[@]}"
    
    sleep 1
done

echo ""
echo "All combinations completed!"

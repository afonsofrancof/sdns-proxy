#!/bin/bash

# Exit on error
set -e

# Default values
TOOL_PATH="./qol"
DOMAINS_FILE="./domains.txt"
OUTPUT_DIR="./results"
INTERFACE="veth1"
TIMEOUT="5s"
SLEEP_TIME="1"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--tool-path)
      TOOL_PATH="$2"
      shift 2
      ;;
    -d|--domains-file)
      DOMAINS_FILE="$2"
      shift 2
      ;;
    -o|--output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -I|--interface)
      INTERFACE="$2"
      shift 2
      ;;
    -T|--timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    -s|--sleep)
      SLEEP_TIME="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -t, --tool-path PATH      Path to qol tool (default: ./qol)"
      echo "  -d, --domains-file PATH   Path to domains file (default: ./domains.txt)"
      echo "  -o, --output-dir PATH     Output directory (default: ./results)"
      echo "  -I, --interface NAME      Network interface (default: veth1)"
      echo "  -T, --timeout DURATION    Timeout duration (default: 5s)"
      echo "  -s, --sleep SECONDS       Sleep between runs (default: 1)"
      echo "  --help                    Show this help"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

echo "Configuration:"
echo "  Tool path: $TOOL_PATH"
echo "  Domains file: $DOMAINS_FILE"
echo "  Output dir: $OUTPUT_DIR"
echo "  Interface: $INTERFACE"
echo "  Timeout: $TIMEOUT"
echo "  Sleep time: ${SLEEP_TIME}s"
echo ""

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
    --interface "$INTERFACE"
    --timeout "$TIMEOUT"
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
    
    sleep "$SLEEP_TIME"
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
    
    sleep "$SLEEP_TIME"
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
    
    sleep "$SLEEP_TIME"
done

echo ""
echo "All combinations completed!"

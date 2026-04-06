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

# Server definitions as associative arrays (name -> url)
declare -A CONN_SERVERS=(
    ["google-dotcp"]="dotcp://8.8.8.8:53"
    ["cloudflare-dotcp"]="dotcp://1.1.1.1:53"
    ["quad9-dotcp"]="dotcp://9.9.9.9:53"
    ["adguard-dotcp"]="dotcp://dns.adguard-dns.com:53"
    ["google-dot"]="tls://8.8.8.8:853"
    ["cloudflare-dot"]="tls://1.1.1.1:853"
    ["quad9-dot"]="tls://9.9.9.9:853"
    ["adguard-dot"]="tls://dns.adguard-dns.com:853"
    ["google-doh"]="https://dns.google/dns-query"
    ["cloudflare-doh"]="https://cloudflare-dns.com/dns-query"
    ["quad9-doh"]="https://dns10.quad9.net/dns-query"
    ["adguard-doh"]="https://dns.adguard-dns.com/dns-query"
)

declare -A QUIC_SERVERS=(
    ["google-doh3"]="doh3://dns.google/dns-query"
    ["cloudflare-doh3"]="doh3://cloudflare-dns.com/dns-query"
    ["adguard-doh3"]="doh3://dns.adguard-dns.com/dns-query"
    ["adguard-doq"]="doq://dns.adguard-dns.com:853"
)

declare -A CONNLESS_SERVERS=(
    ["google-udp"]="udp://8.8.8.8:53"
    ["cloudflare-udp"]="udp://1.1.1.1:53"
    ["quad9-udp"]="udp://9.9.9.9:53"
    ["adguard-udp"]="udp://dns.adguard-dns.com:53"
    ["adguard-dnscrypt"]="sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
    ["quad9-dnscrypt"]="sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ"
)

# Function to get flags suffix for filename
get_flags_suffix() {
    local dnssec="$1"
    local auth="$2"
    local keepalive="$3"
    
    local suffix=""
    if [[ "$dnssec" == "true" ]]; then
        if [[ "$auth" == "true" ]]; then
            suffix="auth"
        else
            suffix="trust"
        fi
    fi
    if [[ "$keepalive" == "true" ]]; then
        if [[ -n "$suffix" ]]; then
            suffix="${suffix}-persist"
        else
            suffix="persist"
        fi
    fi
    echo "$suffix"
}

# Function to run with perf and capture CPU metrics
run_with_perf() {
    local name="$1"
    local url="$2"
    local dnssec="$3"
    local auth="$4"
    local keepalive="$5"
    
    local suffix=$(get_flags_suffix "$dnssec" "$auth" "$keepalive")
    local base_name="${name}"
    if [[ -n "$suffix" ]]; then
        base_name="${name}-${suffix}"
    fi
    local cpu_csv_file="$OUTPUT_DIR/${name%%-*}/${base_name}.cpu.csv"  # e.g., results/cloudflare/dot-trust-persist.cpu.csv
    
    # Write header if needed
    if [[ ! -f "$cpu_csv_file" ]]; then
        echo "timestamp,wall_time_seconds,instructions,cycles,peak_rss_kb" > "$cpu_csv_file"
    fi
    
    # Build command arguments
    local cmd_args=(
        "$DOMAINS_FILE"
        --output-dir "$OUTPUT_DIR"
        --interface "$INTERFACE"
        --timeout "$TIMEOUT"
        -s "$url"
    )
    
    if [[ "$dnssec" == "true" ]]; then
        cmd_args+=(--dnssec)
        if [[ "$auth" == "true" ]]; then
            cmd_args+=(--auth-dnssec)
        fi
    fi
    
    if [[ "$keepalive" == "true" ]]; then
        cmd_args+=(--keep-alive)
    fi
    
    # Create temp files for perf and time output
    local perf_tmp=$(mktemp)
    local time_tmp=$(mktemp)
    
    # Run with perf stat and /usr/bin/time
    local timestamp=$(date -Iseconds)
    
    sudo perf stat -e instructions,cycles \
        -o "$perf_tmp" \
        /usr/bin/time -v \
        "$TOOL_PATH" run "${cmd_args[@]}" 2>"$time_tmp" || true
    
    # Parse perf output
    local instructions=$(grep -oP '\d[\d,]*(?=\s+instructions)' "$perf_tmp" 2>/dev/null | tr -d ',' || echo "0")
    local cycles=$(grep -oP '\d[\d,]*(?=\s+cycles)' "$perf_tmp" 2>/dev/null | tr -d ',' || echo "0")
    local wall_time=$(grep -oP '\d+\.\d+(?= seconds time elapsed)' "$perf_tmp" 2>/dev/null || echo "0")
    
    # Parse /usr/bin/time output for peak RSS
    local peak_rss=$(grep "Maximum resident set size" "$time_tmp" 2>/dev/null | grep -oP '\d+' || echo "0")
    
    # Append to CPU CSV
    echo "${timestamp},${wall_time},${instructions},${cycles},${peak_rss}" >> "$cpu_csv_file"
    
    # Cleanup
    rm -f "$perf_tmp" "$time_tmp"
    
    echo "  -> CPU metrics saved to ${base_name}.cpu.csv"
}

# Function to run servers with given flags
run_server_group() {
    local -n servers=$1
    local dnssec="$2"
    local auth="$3"
    local keepalive="$4"
    local desc="$5"
    
    echo "Running: $desc"
    
    for name in "${!servers[@]}"; do
        local url="${servers[$name]}"
        echo "  Processing: $name ($url)"
        run_with_perf "$name" "$url" "$dnssec" "$auth" "$keepalive"
        sleep "$SLEEP_TIME"
    done
}

echo "=== Running TCP-based protocols (TLS/HTTPS) ==="

# DNSSEC off, Keep off
run_server_group CONN_SERVERS "false" "false" "false" "no-dnssec, no-keepalive"

# DNSSEC off, Keep on
run_server_group CONN_SERVERS "false" "false" "true" "no-dnssec, keepalive"

# DNSSEC on (trust), Keep on
run_server_group CONN_SERVERS "true" "false" "true" "dnssec-trust, keepalive"

# DNSSEC on (auth), Keep on
run_server_group CONN_SERVERS "true" "true" "true" "dnssec-auth, keepalive"

echo ""
echo "=== Running QUIC-based protocols (DoH3/DoQ) ==="

# DNSSEC off
run_server_group QUIC_SERVERS "false" "false" "false" "no-dnssec"

# DNSSEC on (trust)
run_server_group QUIC_SERVERS "true" "false" "false" "dnssec-trust"

# DNSSEC on (auth)
run_server_group QUIC_SERVERS "true" "true" "false" "dnssec-auth"

echo ""
echo "=== Running connectionless protocols (UDP) ==="

# DNSSEC off
run_server_group CONNLESS_SERVERS "false" "false" "false" "no-dnssec"

# DNSSEC on (trust)
run_server_group CONNLESS_SERVERS "true" "false" "false" "dnssec-trust"

# DNSSEC on (auth)
run_server_group CONNLESS_SERVERS "true" "true" "false" "dnssec-auth"

echo ""
echo "All combinations completed!"

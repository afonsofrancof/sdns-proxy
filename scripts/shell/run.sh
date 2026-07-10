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
DRY_RUN="false"

DNSSEC_DOMAINS_FILE="./domains_signed.txt"
DNSSEC_OUTPUT_DIR="./results-dnssec"

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
    -n|--dry-run)
      DRY_RUN="true"
      shift
      ;;
    --dnssec-domains)
      DNSSEC_DOMAINS_FILE="$2"
      shift 2
      ;;
    --dnssec-output)
      DNSSEC_OUTPUT_DIR="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -t, --tool-path PATH       Path to qol tool (default: ./qol)"
      echo "  -d, --domains-file PATH    Domains file for the general runs (default: ./domains.txt)"
      echo "  -o, --output-dir PATH      Output dir for the general runs (default: ./results)"
      echo "  -I, --interface NAME       Network interface (default: veth1)"
      echo "  -T, --timeout DURATION     Timeout duration (default: 5s)"
      echo "  -s, --sleep SECONDS        Sleep between runs (default: 1)"
      echo "  -n, --dry-run              Print the scenarios that would run, then exit"
      echo "      --dnssec-domains PATH  Signed-domain list for DNSSEC runs (default: ./domains_signed.txt)"
      echo "      --dnssec-output PATH   Output dir for DNSSEC runs (default: ./results-dnssec)"
      echo "      --help                 Show this help"
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
echo "  DNSSEC domains file: $DNSSEC_DOMAINS_FILE"
echo "  DNSSEC output dir: $DNSSEC_OUTPUT_DIR"
echo "  Interface: $INTERFACE"
echo "  Timeout: $TIMEOUT"
echo "  Sleep time: ${SLEEP_TIME}s"
echo "  Dry run: $DRY_RUN"
echo ""

SC_NAME=()
SC_URL=()
SC_DNSSEC=()
SC_AUTH=()
SC_KEEP=()
SC_DOMAINS=()   # per-scenario domains file
SC_OUTDIR=()    # per-scenario output dir

add() {  # add <name> <url> <dnssec> <auth> <keepalive>   (general workload)
    SC_NAME+=("$1"); SC_URL+=("$2"); SC_DNSSEC+=("$3"); SC_AUTH+=("$4"); SC_KEEP+=("$5")
    SC_DOMAINS+=("$DOMAINS_FILE"); SC_OUTDIR+=("$OUTPUT_DIR")
}

add_dnssec() {  # same signature, but pins the signed list + DNSSEC output dir
    SC_NAME+=("$1"); SC_URL+=("$2"); SC_DNSSEC+=("$3"); SC_AUTH+=("$4"); SC_KEEP+=("$5")
    SC_DOMAINS+=("$DNSSEC_DOMAINS_FILE"); SC_OUTDIR+=("$DNSSEC_OUTPUT_DIR")
}

# Protocol comparison - DNSSEC off, non-persistent.
# The primary comparison axis: full encryption cost, handshake included.
# All transports.
add google-dotcp      "dotcp://8.8.8.8:53"                      false false false
add cloudflare-dotcp  "dotcp://1.1.1.1:53"                      false false false
add quad9-dotcp       "dotcp://9.9.9.10:53"                      false false false
add adguard-dotcp     "dotcp://94.140.14.140:53"                false false false

add google-dot        "tls://8.8.8.8:853"                       false false false
add cloudflare-dot    "tls://1.1.1.1:853"                       false false false
add quad9-dot         "tls://9.9.9.10:853"                       false false false
add adguard-dot       "tls://94.140.14.140:853"                 false false false

add google-doh        "https://dns.google/dns-query"            false false false
add cloudflare-doh    "https://cloudflare-dns.com/dns-query"    false false false
add quad9-doh         "https://dns10.quad9.net/dns-query"       false false false
add adguard-doh       "https://unfiltered.adguard-dns.com/dns-query"   false false false

add google-doh3       "doh3://dns.google/dns-query"             false false false
add cloudflare-doh3   "doh3://cloudflare-dns.com/dns-query"     false false false
add adguard-doh3      "doh3://unfiltered.adguard-dns.com/dns-query"    false false false
add adguard-doq       "doq://unfiltered.adguard-dns.com:853"    false false false

add google-doudp      "udp://8.8.8.8:53"                        false false false
add cloudflare-doudp  "udp://1.1.1.1:53"                        false false false
add quad9-doudp       "udp://9.9.9.10:53"                        false false false
add adguard-doudp     "udp://94.140.14.140:53"                  false false false
add adguard-dnscrypt  "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20" false false false
add quad9-dnscrypt    "sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ" false false false

# Persistence contrast - DNSSEC off, persistent.
# Tested for TCP-based protocols. QUIC makes no sense because of 0-RTT.
add google-dotcp      "dotcp://8.8.8.8:53"                      false false true
add cloudflare-dotcp  "dotcp://1.1.1.1:53"                      false false true
add quad9-dotcp       "dotcp://9.9.9.10:53"                      false false true
add adguard-dotcp     "dotcp://94.140.14.140:53"                false false true

add google-dot        "tls://8.8.8.8:853"                       false false true
add cloudflare-dot    "tls://1.1.1.1:853"                       false false true
add quad9-dot         "tls://9.9.9.10:853"                       false false true
add adguard-dot       "tls://94.140.14.140:853"                 false false true

add google-doh        "https://dns.google/dns-query"            false false true
add cloudflare-doh    "https://cloudflare-dns.com/dns-query"    false false true
add quad9-doh         "https://dns10.quad9.net/dns-query"       false false true
add adguard-doh       "https://unfiltered.adguard-dns.com/dns-query"   false false true

# ==========================================================================
# DNSSEC scenarios: signed domain list + separate output dir (results-dnssec).
# off / trust / auth all share the signed list, so the domain set is held
# constant across the three modes. Non-persistent throughout.
# ==========================================================================

# DNSSEC off - baseline ON THE SIGNED LIST (separate from the protocol-comparison
# off runs above, which use the general list).
add_dnssec google-dotcp      "dotcp://8.8.8.8:53"                      false false false
add_dnssec cloudflare-dotcp  "dotcp://1.1.1.1:53"                      false false false
add_dnssec quad9-dotcp       "dotcp://9.9.9.10:53"                     false false false
add_dnssec adguard-dotcp     "dotcp://94.140.14.140:53"               false false false

add_dnssec google-dot        "tls://8.8.8.8:853"                       false false false
add_dnssec cloudflare-dot    "tls://1.1.1.1:853"                       false false false
add_dnssec quad9-dot         "tls://9.9.9.10:853"                      false false false
add_dnssec adguard-dot       "tls://94.140.14.140:853"                false false false

add_dnssec google-doh        "https://dns.google/dns-query"            false false false
add_dnssec cloudflare-doh    "https://cloudflare-dns.com/dns-query"    false false false
add_dnssec quad9-doh         "https://dns10.quad9.net/dns-query"       false false false
add_dnssec adguard-doh       "https://unfiltered.adguard-dns.com/dns-query"  false false false

add_dnssec google-doh3       "doh3://dns.google/dns-query"             false false false
add_dnssec cloudflare-doh3   "doh3://cloudflare-dns.com/dns-query"     false false false
add_dnssec adguard-doh3      "doh3://unfiltered.adguard-dns.com/dns-query"   false false false
add_dnssec adguard-doq       "doq://unfiltered.adguard-dns.com:853"   false false false

add_dnssec google-doudp      "udp://8.8.8.8:53"                        false false false
add_dnssec cloudflare-doudp  "udp://1.1.1.1:53"                        false false false
add_dnssec quad9-doudp       "udp://9.9.9.10:53"                       false false false
add_dnssec adguard-doudp     "udp://94.140.14.140:53"                 false false false
add_dnssec adguard-dnscrypt  "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20" false false false
add_dnssec quad9-dnscrypt    "sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ" false false false

# DNSSEC trust - non-persistent, signed list.
add_dnssec google-dotcp      "dotcp://8.8.8.8:53"                      true false false
add_dnssec cloudflare-dotcp  "dotcp://1.1.1.1:53"                      true false false
add_dnssec quad9-dotcp       "dotcp://9.9.9.10:53"                     true false false
add_dnssec adguard-dotcp     "dotcp://94.140.14.140:53"               true false false

add_dnssec google-dot        "tls://8.8.8.8:853"                       true false false
add_dnssec cloudflare-dot    "tls://1.1.1.1:853"                       true false false
add_dnssec quad9-dot         "tls://9.9.9.10:853"                      true false false
add_dnssec adguard-dot       "tls://94.140.14.140:853"                true false false

add_dnssec google-doh        "https://dns.google/dns-query"            true false false
add_dnssec cloudflare-doh    "https://cloudflare-dns.com/dns-query"    true false false
add_dnssec quad9-doh         "https://dns10.quad9.net/dns-query"       true false false
add_dnssec adguard-doh       "https://unfiltered.adguard-dns.com/dns-query"  true false false

add_dnssec google-doh3       "doh3://dns.google/dns-query"             true false false
add_dnssec cloudflare-doh3   "doh3://cloudflare-dns.com/dns-query"     true false false
add_dnssec adguard-doh3      "doh3://unfiltered.adguard-dns.com/dns-query"   true false false
add_dnssec adguard-doq       "doq://unfiltered.adguard-dns.com:853"   true false false

add_dnssec google-doudp      "udp://8.8.8.8:53"                        true false false
add_dnssec cloudflare-doudp  "udp://1.1.1.1:53"                        true false false
add_dnssec quad9-doudp       "udp://9.9.9.10:53"                       true false false
add_dnssec adguard-doudp     "udp://94.140.14.140:53"                 true false false
add_dnssec adguard-dnscrypt  "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20" true false false
add_dnssec quad9-dnscrypt    "sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ" true false false

# DNSSEC auth - DoUDP only.
# auth walks the chain of trust over plain DoUDP regardless of the protocol.
add_dnssec adguard-doudp     "udp://94.140.14.140:53"                 true true false

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
    local domains_file="$6"
    local output_dir="$7"

    local suffix=$(get_flags_suffix "$dnssec" "$auth" "$keepalive")
    local provider="${name%%-*}"
    local protocol="${name#*-}"
    local base_name="${protocol}"
    if [[ -n "$suffix" ]]; then
        base_name="${protocol}-${suffix}"
    fi
    local cpu_csv_file="$output_dir/${provider}/${base_name}.cpu.csv"

    # Create directory if needed
    mkdir -p "$(dirname "$cpu_csv_file")"

    # Write header if needed
    if [[ ! -f "$cpu_csv_file" ]]; then
        echo "timestamp,wall_time_seconds,instructions,cycles" > "$cpu_csv_file"
    fi

    # Build command arguments
    local cmd_args=(
        "$domains_file"
        --output-dir "$output_dir"
        --interface "$INTERFACE"
        --timeout "$TIMEOUT"
        -s "$url"
    )

    if [[ "$dnssec" == "true" ]]; then
        cmd_args+=(--dnssec)
        if [[ "$auth" == "true" ]]; then
            cmd_args+=(--authoritative-dnssec)
        fi
    fi

    if [[ "$keepalive" == "true" ]]; then
        cmd_args+=(--keep-alive)
    fi

    # Create temp file for perf
    local perf_tmp=$(mktemp)

    # Run with perf stat
    local timestamp=$(date -Iseconds)

    perf stat -e instructions,cycles \
        -o "$perf_tmp" \
        "$TOOL_PATH" run "${cmd_args[@]}" || true

    # Parse perf output
    local instructions=$(grep -oP '\d[\d,]*(?=\s+instructions)' "$perf_tmp" 2>/dev/null | tr -d ',' || echo "0")
    local cycles=$(grep -oP '\d[\d,]*(?=\s+cycles)' "$perf_tmp" 2>/dev/null | tr -d ',' || echo "0")
    local wall_time=$(grep -oP '\d+\.\d+(?= seconds time elapsed)' "$perf_tmp" 2>/dev/null || echo "0")

    # Append to CPU CSV
    echo "${timestamp},${wall_time},${instructions},${cycles}" >> "$cpu_csv_file"

    # Cleanup
    rm -f "$perf_tmp"

    echo "  -> CPU metrics saved to ${output_dir}/${provider}/${base_name}.cpu.csv"
}

echo "Total scenarios: ${#SC_NAME[@]}"
echo ""

# Guard: all scenario arrays must be the same length (they desync only if a row
# was added without going through add()/add_dnssec()).
_n=${#SC_NAME[@]}
if (( ${#SC_URL[@]} != _n || ${#SC_DNSSEC[@]} != _n || ${#SC_AUTH[@]} != _n \
      || ${#SC_KEEP[@]} != _n || ${#SC_DOMAINS[@]} != _n || ${#SC_OUTDIR[@]} != _n )); then
    echo "ERROR: scenario arrays are misaligned (lengths differ). Check add()/add_dnssec() calls." >&2
    exit 1
fi

for i in "${!SC_NAME[@]}"; do
    name="${SC_NAME[$i]}"
    url="${SC_URL[$i]}"
    dnssec="${SC_DNSSEC[$i]}"
    auth="${SC_AUTH[$i]}"
    keepalive="${SC_KEEP[$i]}"
    domains_file="${SC_DOMAINS[$i]}"
    output_dir="${SC_OUTDIR[$i]}"

    suffix=$(get_flags_suffix "$dnssec" "$auth" "$keepalive")
    provider="${name%%-*}"
    protocol="${name#*-}"
    label="${protocol}"
    [[ -n "$suffix" ]] && label="${protocol}-${suffix}"

    if [[ "$DRY_RUN" == "true" ]]; then
        printf '[dry] %-28s dnssec=%-5s auth=%-5s keepalive=%-5s  [%s] -> %s/%s/%s\n' \
            "$name" "$dnssec" "$auth" "$keepalive" \
            "$(basename "$domains_file")" "$output_dir" "$provider" "$label"
        continue
    fi

    echo "Processing: $name ($url)  [dnssec=$dnssec auth=$auth keepalive=$keepalive, domains=$(basename "$domains_file"), out=$output_dir]"
    run_with_perf "$name" "$url" "$dnssec" "$auth" "$keepalive" "$domains_file" "$output_dir"
    sleep "$SLEEP_TIME"
done

echo ""
if [[ "$DRY_RUN" == "true" ]]; then
    echo "Dry run complete - nothing was executed."
else
    echo "All scenarios completed!"
fi

#!/bin/bash

TOOL_PATH="$1"/"qol"
DOMAINS_FILE="$1"/"domains.txt"
OUTPUT_DIR="$1"/"results"

# All servers in one command (same as yours)
SERVERS=(
    -s "udp://8.8.8.8:53"
    -s "udp://1.1.1.1:53"
    -s "udp://9.9.9.9:53"
    -s "udp://dns.adguard-dns.com:53"
    -s "tls://8.8.8.8:853"
    -s "tls://1.1.1.1:853"
    -s "tls://9.9.9.9:853"
    -s "tls://dns.adguard-dns.com:853"
    -s "https://dns.google/dns-query"
    -s "https://cloudflare-dns.com/dns-query"
    -s "https://dns10.quad9.net/dns-query"
    -s "https://dns.adguard-dns.com/dns-query"
    -s "doh3://dns.google/dns-query"
    -s "doh3://cloudflare-dns.com/dns-query"
    -s "doh3://dns.adguard-dns.com/dns-query"
    -s "doq://dns.adguard-dns.com:853"
)

# Common args
COMMON_ARGS=(
    "$DOMAINS_FILE"
    --interface eth0
    --timeout 5s
    "${SERVERS[@]}"
)

# Define all combinations as arrays of extra flags (no suffixes here, since flags are in filenames)
COMBINATIONS=(
    # DNSSEC off, Keep off
    ""

    # DNSSEC off, Keep on
    "--keep-alive"

    # DNSSEC on (trust), Keep off
    "--dnssec"

    # DNSSEC on (trust), Keep on
    "--dnssec --keep-alive"

    # DNSSEC on (auth), Keep off
    "--dnssec --auth-dnssec"

    # DNSSEC on (auth), Keep on
    "--dnssec --auth-dnssec --keep-alive"
)

# Run each combination with a unique timestamped output dir
for ((i=0; i<${#COMBINATIONS[@]}; i++)); do
    FLAGS=${COMBINATIONS[$i]}

    # Generate a unique timestamp for this run (YYYYMMDD_HHMMSS)
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

    OUTPUT_PATH="${OUTPUT_DIR}/run_${TIMESTAMP}"

    echo "Running combination: $FLAGS (output: $OUTPUT_PATH)"

    # Convert FLAGS string to array (split by space)
    FLAGS_ARRAY=($FLAGS)

    sudo "$TOOL_PATH" run \
        --output-dir "$OUTPUT_PATH" \
        "${COMMON_ARGS[@]}" \
        "${FLAGS_ARRAY[@]}"
    
    sleep 1
done

echo "All combinations completed!"

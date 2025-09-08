#!/bin/bash

TOOL_PATH="$1"/"qol"
DOMAINS_FILE="$1"/"domains.txt"
OUTPUT_DIR="$1"/"results"
TIMESTAMP=$(date '+%Y%m%d_%H%M')

# All servers in one command
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
    -s "doq://dns.adguard-dns.com:853"
)

# Run with DNSSEC off
sudo "$TOOL_PATH" run "$DOMAINS_FILE" \
    --output-dir "${OUTPUT_DIR}/run_${TIMESTAMP}_dnssec_off" \
    --interface eth0 \
    --timeout 5s \
    "${SERVERS[@]}"

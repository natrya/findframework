#!/usr/bin/env bash
#
# findframework.sh - Enumerate subdomains (passive) and fingerprint web
# frameworks/technologies (active) for a target domain.
#
# Author: Ryan Fabella
# Usage: ./findframework.sh -d <domain> [-o outdir] [-r rate_limit] [-p]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DOMAIN=""
OUTDIR=""
RATE_LIMIT=100
PASSIVE_ONLY=0

usage() {
    cat <<EOF
Usage: $0 -d <domain> [-o outdir] [-r rate_limit] [-p]

  -d   target domain (required, e.g. example.com)
  -o   output directory (default: ./output/<domain>_<timestamp>)
  -r   rate limit for httpx/nuclei requests-per-second (default: 100)
  -p   passive-only mode (skip whatweb/nuclei/wafw00f active fingerprinting)
  -h   show this help
EOF
}

while getopts "d:o:r:ph" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        r) RATE_LIMIT="$OPTARG" ;;
        p) PASSIVE_ONLY=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "Error: -d <domain> is required" >&2
    usage
    exit 1
fi

# Base directory that holds every run's output (one timestamped subfolder each).
OUTPUT_BASE="${OUTPUT_BASE:-$SCRIPT_DIR/output}"
if [[ -z "$OUTDIR" ]]; then
    OUTDIR="$OUTPUT_BASE/${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$OUTDIR"

log() {
    echo "[$(date +%H:%M:%S)] $*"
}

# --- dependency check -------------------------------------------------
REQUIRED_BINS=(subfinder amass httpx whatweb nuclei wafw00f jq curl python3)
MISSING=()
for bin in "${REQUIRED_BINS[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || MISSING+=("$bin")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "Error: missing required tools: ${MISSING[*]}" >&2
    exit 1
fi

log "Target: $DOMAIN"
log "Output directory: $OUTDIR"
log "Rate limit: $RATE_LIMIT rps"
[[ "$PASSIVE_ONLY" -eq 1 ]] && log "Mode: passive-only"

# --- 1. Passive subdomain enumeration ---------------------------------
log "Step 1/4: passive subdomain enumeration"

SUBS_RAW="$OUTDIR/subdomains_raw.txt"
: > "$SUBS_RAW"

log "  running subfinder"
# -stats prints per-source result/error counts on stderr; capture it so we can
# see which passive sources fired (and which were skipped for missing API keys).
SUBFINDER_STATS="$OUTDIR/subfinder_stats.txt"
subfinder -d "$DOMAIN" -all -silent -stats >> "$SUBS_RAW" 2>"$SUBFINDER_STATS"
if [[ -s "$SUBFINDER_STATS" ]]; then
    # pull the busiest sources for a quick at-a-glance log line
    top_src=$(grep -E '^\s+\S+\s+' "$SUBFINDER_STATS" \
        | awk 'NF>=4 && $3 ~ /^[0-9]+$/ && $3>0 {print $3"|"$1}' \
        | sort -t'|' -k1 -rn | head -3 \
        | awk -F'|' '{printf "%s(%s) ", $2, $1}')
    [[ -n "$top_src" ]] && log "  top sources: ${top_src%% }"
    log "  subfinder stats -> $SUBFINDER_STATS"
fi

log "  running amass (passive)"
amass enum -passive -d "$DOMAIN" -silent >> "$SUBS_RAW" 2>/dev/null

log "  querying crt.sh"
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null \
    | tr ',' '\n' \
    >> "$SUBS_RAW"

# normalize: lowercase, strip wildcard prefixes, drop blanks, dedupe
SUBS_FILE="$OUTDIR/subdomains.txt"
sed 's/^\*\.//' "$SUBS_RAW" \
    | tr '[:upper:]' '[:lower:]' \
    | grep -E "(^|\.)${DOMAIN//./\\.}\$" \
    | sed '/^$/d' \
    | sort -u > "$SUBS_FILE"

SUB_COUNT=$(wc -l < "$SUBS_FILE" | tr -d ' ')
log "  found $SUB_COUNT unique subdomains -> $SUBS_FILE"

if [[ "$SUB_COUNT" -eq 0 ]]; then
    echo "Error: no subdomains found for $DOMAIN, aborting" >&2
    exit 1
fi

# --- 2. Liveness + lightweight tech-detect (httpx) ---------------------
log "Step 2/4: liveness probing + tech-detect (httpx)"

HTTPX_JSON="$OUTDIR/httpx_output.json"
LIVE_HOSTS="$OUTDIR/live_hosts.txt"

httpx -l "$SUBS_FILE" -silent -status-code -title -tech-detect -web-server \
    -follow-redirects -rl "$RATE_LIMIT" -json -o "$HTTPX_JSON" 2>/dev/null

jq -r 'select(.url != null) | .url' "$HTTPX_JSON" 2>/dev/null | sort -u > "$LIVE_HOSTS"
LIVE_COUNT=$(wc -l < "$LIVE_HOSTS" | tr -d ' ')
log "  $LIVE_COUNT live hosts -> $LIVE_HOSTS"

WHATWEB_JSON="$OUTDIR/whatweb_output.json"
NUCLEI_JSONL="$OUTDIR/nuclei_tech.jsonl"
WAFW00F_TXT="$OUTDIR/wafw00f_output.txt"
: > "$WHATWEB_JSON"
: > "$NUCLEI_JSONL"
: > "$WAFW00F_TXT"

if [[ "$LIVE_COUNT" -eq 0 ]]; then
    log "  no live hosts found, skipping active fingerprinting"
elif [[ "$PASSIVE_ONLY" -eq 1 ]]; then
    log "Step 3/4: skipped (passive-only mode)"
else
    # --- 3. Active deep fingerprint -------------------------------
    log "Step 3/4: active fingerprinting (whatweb, nuclei, wafw00f)"

    log "  running whatweb (aggression 3)"
    whatweb -a 3 --log-json="$WHATWEB_JSON" -i "$LIVE_HOSTS" >/dev/null 2>&1

    log "  running nuclei (technologies templates)"
    nuclei -l "$LIVE_HOSTS" -t technologies/ -rl "$RATE_LIMIT" -silent \
        -jsonl -o "$NUCLEI_JSONL" 2>/dev/null

    log "  running wafw00f"
    wafw00f -i "$LIVE_HOSTS" -o "$WAFW00F_TXT" >/dev/null 2>&1
fi

# --- 4. Merge & report --------------------------------------------------
log "Step 4/4: merging findings and generating report"

python3 "$SCRIPT_DIR/merge_findings.py" \
    --domain "$DOMAIN" \
    --httpx "$HTTPX_JSON" \
    --whatweb "$WHATWEB_JSON" \
    --nuclei "$NUCLEI_JSONL" \
    --wafw00f "$WAFW00F_TXT" \
    --subdomains "$SUBS_FILE" \
    --outdir "$OUTDIR"

log "Done. Report: $OUTDIR/report.md  |  JSON: $OUTDIR/results.json"

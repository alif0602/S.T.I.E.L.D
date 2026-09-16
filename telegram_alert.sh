#!/bin/bash

# ==== Prevent overlapping runs (fixes duplicate alerts) ====
LOCKFILE="/tmp/tpot_alert.lock"
exec 200>"$LOCKFILE"
flock -n 200 || exit 0
source "$(dirname "$0")/secrets.env"
STATE_DIR="/tmp/tpot_alert_state"
mkdir -p "$STATE_DIR"

# ==== Senders ====
# printf '%b' converts literal "\n" (backslash+n) into a REAL newline
# before sending — this is what fixes the Telegram "\n" showing as text.

send_email() {
    local body
    body=$(printf '%b' "$1")
    { echo "Subject: T-Pot Alert - Attack Detected"; echo; echo "$body"; } \
        | msmtp -a gmail aliffarhanjalil06@gmail.com
}

send_telegram() {
    local body
    body=$(printf '%b' "$1")
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${CHAT_ID}" \
        --data-urlencode "text=${body}" > /dev/null
}

get_count() {
    local file="$STATE_DIR/$1.count"
    [ -f "$file" ] && cat "$file" || echo 0
}

save_count() {
    echo "$2" > "$STATE_DIR/$1.count"
}

# ==== Honeypots to monitor ====
# Format: [container_name]="Attack Type|grep_keyword"
declare -A HONEYPOTS=(
    ["cowrie"]="Brute Force SSH/Telnet|login attempt"
    ["dionaea"]="Malware/Exploit Attempt|connection"
    ["honeytrap"]="Port Scan/Connection Attack|attacker"
    ["h0neytr4p"]="Port Scan/Connection Attack|attacker"
    ["mailoney"]="SMTP Spam/Relay Attempt|MAIL FROM"
    ["heralding"]="Credential Harvesting|login"
    ["ciscoasa"]="VPN/Cisco Exploit Attempt|Client"
    ["conpot_ipmi"]="ICS/SCADA Attack (IPMI)|new connection"
    ["conpot_kamstrup_382"]="ICS/SCADA Attack (Kamstrup)|new connection"
    ["conpot_iec104"]="ICS/SCADA Attack (IEC104)|new connection"
    ["conpot_guardian_ast"]="ICS/SCADA Attack (Guardian AST)|new connection"
    ["adbhoney"]="Android Debug Bridge Exploit|connect"
    ["redishoneypot"]="Redis Exploit Attempt|connect"
    ["elasticpot"]="Elasticsearch Exploit Attempt|request"
    ["wordpot"]="WordPress Exploit/Scan Attempt|request"
    ["medpot"]="Medical HL7 Exploit Attempt|MSH"
    ["ipphoney"]="IPP Printer Exploit Attempt|request"
    ["sentrypeer"]="VoIP/SIP Attack Attempt|INVITE"
    ["dicompot"]="DICOM Medical Imaging Attack|Association"
    ["miniprint"]="Printer (PJL) Exploit Attempt|connection"
)

ALERT_MSG=""
TOTAL_NEW=0

for container in "${!HONEYPOTS[@]}"; do
    if ! docker ps --format '{{.Names}}' | grep -qx "$container"; then
        continue
    fi

    IFS="|" read -r ATTACK_TYPE PATTERN <<< "${HONEYPOTS[$container]}"

    COUNT=$(docker logs "$container" --since=1m 2>&1 | grep -ic "$PATTERN")
    LAST=$(get_count "$container")

    if [ "$COUNT" -gt 0 ] && [ "$COUNT" -gt "$LAST" ]; then
        SRC_IP=$(docker logs "$container" --since=1m 2>&1 | grep -oP '\d+\.\d+\.\d+\.\d+' | tail -1)
        ALERT_MSG+="* ${ATTACK_TYPE} [${container}]\n"
        ALERT_MSG+="  IP: ${SRC_IP:-Unknown}\n"
        ALERT_MSG+="  Events: ${COUNT}\n\n"
        TOTAL_NEW=$((TOTAL_NEW + 1))
    fi

    save_count "$container" "$COUNT"
done

# ==== Tanner (Web Attack - reads log file directly, not docker logs) ====
TANNER_LOG="/home/paan/tpotce/data/tanner/log/tanner_report.json"
TANNER_STATE="$STATE_DIR/tanner_last_ts"
if [ -f "$TANNER_LOG" ]; then
    LAST_TS=$( [ -f "$TANNER_STATE" ] && cat "$TANNER_STATE" || echo "" )

    TANNER_RAW=$(tail -n 200 "$TANNER_LOG" | jq -r --arg last "$LAST_TS" '
        select(.timestamp > $last) |
        [.timestamp, .path, (.headers.cookie // ""), (.peer.ip // "Unknown")] |
        if (.[1] | test("\\.\\./")) or (.[2] | test("\\.\\./")) then
            "\(.[0])|Path Traversal/LFI Attempt|\(.[3])|\(.[1])"
        elif (.[1] | test("select|union|<script|onerror|alert\\(")) or (.[2] | test("select|union|<script")) then
            "\(.[0])|XSS/SQL Injection Attempt|\(.[3])|\(.[1])"
        else
            "\(.[0])|Web Probe/Recon|\(.[3])|\(.[1])"
        end
    ' 2>/dev/null | sort -u | tail -5)

    if [ -n "$TANNER_RAW" ]; then
        while IFS='|' read -r TTS WTYPE WIP WPATH; do
            ALERT_MSG+="* ${WTYPE} [tanner]\n"
            ALERT_MSG+="  IP: ${WIP}\n"
            ALERT_MSG+="  Path: ${WPATH}\n\n"
        done <<< "$TANNER_RAW"
        TOTAL_NEW=$((TOTAL_NEW + 1))
        echo "$TANNER_RAW" | awk -F'|' '{print $1}' | sort | tail -1 > "$TANNER_STATE"
    fi
fi

# ==== Suricata (Network IDS - richest attack classification) ====
SURICATA_LOG="/home/paan/tpotce/data/suricata/log/eve.json"
SURICATA_STATE="$STATE_DIR/suricata_last_ts"
if [ -f "$SURICATA_LOG" ]; then
    LAST_TS=$( [ -f "$SURICATA_STATE" ] && cat "$SURICATA_STATE" || echo "" )

    SURICATA_RAW=$(tail -n 500 "$SURICATA_LOG" 2>/dev/null \
        | jq -r --arg last "$LAST_TS" 'select(.event_type=="alert")
            | select(.timestamp > $last)
            | select(.alert.severity < 3)
            | select(.alert.category != "Potentially Bad Traffic")
            | select(.alert.category != "Generic Protocol Command Decay")
            | select(.alert.signature | test("^ET INFO|^ET POLICY|^SURICATA STREAM") | not)
            | (.alert.signature) as $sig
            | (
                if ($sig | test("scan"; "i")) then "Scanning"
                elif ($sig | test("brute ?force"; "i")) then "Brute Force"
                elif ($sig | test("rce|exploit|remote code execution"; "i")) then "Exploit Attempt"
                elif ($sig | test("trojan|malware|botnet| c2 |c2 traffic"; "i")) then "Malware/C2 Traffic"
                elif ($sig | test("sql injection|cross site|xss|lfi|rfi|web application attack"; "i")) then "Web Attack"
                elif ($sig | test("denial of service| dos "; "i")) then "Denial of Service"
                else .alert.category
                end
              ) as $simple
            | "\(.timestamp)|\($simple)|\($sig)|\(.src_ip)"' 2>/dev/null \
        | sort -u | tail -5)

    if [ -n "$SURICATA_RAW" ]; then
        while IFS='|' read -r STS SCAT SSIG SIP; do
            ALERT_MSG+="* ${SCAT} [suricata]\n"
            ALERT_MSG+="  IP: ${SIP}\n"
            ALERT_MSG+="  Detail: ${SSIG}\n\n"
        done <<< "$SURICATA_RAW"
        TOTAL_NEW=$((TOTAL_NEW + 1))
        echo "$SURICATA_RAW" | awk -F'|' '{print $1}' | sort | tail -1 > "$SURICATA_STATE"
    fi
fi

# ==== Send alert if any new attack detected ====
if [ "$TOTAL_NEW" -gt 0 ]; then
    MESSAGE="T-POT SECURITY ALERT\n"
    MESSAGE+="Time: $(date '+%d/%m/%Y %H:%M:%S')\n"
    MESSAGE+="Attack type(s) detected: ${TOTAL_NEW}\n\n"
    MESSAGE+="${ALERT_MSG}"
    MESSAGE+="Check Kibana dashboard for full analysis."

    send_telegram "$MESSAGE"
    send_email "$MESSAGE"
fi

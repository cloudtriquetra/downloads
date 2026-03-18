#!/bin/bash

# Define the Host FQDN
FQDN=$(hostname -f)
TMP_FILE="/tmp/cert_data.tmp"
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm" > "$TMP_FILE"

# 1. Get all numeric ports (Listen, established, or forwarded)
ports=$(sudo netstat -tanpu | awk '{print $4}' | grep -oE '[0-9]+$' | sort -u)

for port in $ports; do
    # Try connecting with SNI
    cert_raw=$(timeout 2 openssl s_client -connect 127.0.0.1:"$port" -servername "$FQDN" </dev/null 2>/dev/null)

    if [[ -n "$cert_raw" ]]; then
        # Parse certificate
        cert_info=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null)
        
        if [[ -n "$cert_info" ]]; then
            # COMMON NAME - Match the "Fake Certificate" logic specifically
            if [[ "$cert_raw" == *"Kubernetes Ingress Controller Fake Certificate"* ]]; then
                cn="Kubernetes Ingress Controller Fake Certificate"
                issuer="Kubernetes Ingress Controller Fake Certificate"
            else
                cn=$(echo "$cert_info" | grep "Subject:" | sed -n 's/.*CN = //p' | cut -d',' -f1 | xargs)
                issuer=$(echo "$cert_info" | grep "Issuer:" | sed -n 's/.*CN = //p' | cut -d',' -f1 | xargs)
            fi

            # SERIAL NUMBER - Keeping colons and uppercase to match your photo
            serial=$(echo "$cert_raw" | openssl x509 -noout -serial 2>/dev/null | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
            # Format serial to add colons every 2 characters if they are missing
            if [[ ! "$serial" == *":"* ]]; then
                serial=$(echo "$serial" | sed 's/../&:/g; s/:$//')
            fi

            # DISCOVERY SOURCE
            discovery="$FQDN:$port"

            # ALGORITHM
            algo=$(echo "$cert_info" | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

            # Append to temp file
            echo "${cn:-[Unknown]},$serial,${issuer:-[Unknown]},$discovery,$algo" >> "$TMP_FILE"
        fi
    fi
done

# 2. GROUPING LOGIC
# This merges multiple discovery sources (ports) into one line per certificate
awk -F, 'BEGIN {OFS=","} 
NR==1 {print; next} 
{
    key=$1 FS $2 FS $3; 
    if (discovery[key] == "") {
        discovery[key]=$4; 
        algo[key]=$5
    } else {
        discovery[key]=discovery[key]"; "$4
    }
} 
END {
    for (k in discovery) print k, discovery[k], algo[k]
}' "$TMP_FILE"

rm "$TMP_FILE"

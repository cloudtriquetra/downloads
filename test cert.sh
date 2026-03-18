#!/bin/bash

# Define Host Info
HOST_FQDN=$(hostname -f)
TARGET_IP=$(hostname -I | awk '{print $1}')
TMP_FILE=$(mktemp)

# 1. UNIVERSAL DISCOVERY: netstat + iptables + ipvsadm
# This covers every possible way a port can be "open" in Linux/K8s
ports=$( ( 
    sudo netstat -tanpu | grep LISTEN | awk '{print $4}' | rev | cut -d: -f1 | rev;
    sudo iptables -t nat -L -n | grep -oE "dpt:[0-9]+" | cut -d: -f2;
    sudo ipvsadm -L -n 2>/dev/null | grep -oE ":[0-9]+ " | tr -d ': '
) | grep -E '^[0-9]+$' | sort -u)

for port in $ports; do
    if [ "$port" -gt 49151 ] || [ "$port" -eq 0 ]; then continue; fi

    # Probe the primary interface IP
    raw_cert=$(echo | timeout 2 openssl s_client -connect "$TARGET_IP":"$port" -servername "$HOST_FQDN" 2>/dev/null)

    if [[ "$raw_cert" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        clean_cert=$(echo "$raw_cert" | openssl x509)

        # Extraction logic
        cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        issuer=$(echo "$clean_cert" | openssl x509 -noout -issuer -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        
        # Match the "Red Entry" branding
        if [[ "$raw_cert" == *"Fake Certificate"* ]]; then
            cn="Kubernetes Ingress Controller Fake Certificate"
            issuer="Kubernetes Ingress Controller Fake Certificate"
        fi

        # Serial Number with Colons
        serial=$(echo "$clean_cert" | openssl x509 -noout -serial | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        [[ ! "$serial" == *":"* ]] && serial=$(echo "$serial" | sed 's/..\B/&:/g')
        
        algo=$(echo "$clean_cert" | openssl x509 -noout -text | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        echo "$serial|$cn|$issuer|$algo|$HOST_FQDN:$port" >> "$TMP_FILE"
    fi
done

# 2. Output CSV
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

if [ -s "$TMP_FILE" ]; then
    awk -F'|' '
    {
        serial=$1; cn=$2; issuer=$3; algo=$4; endpoint=$5;
        if (!(serial in seen)) {
            order[++count] = serial; cns[serial] = cn; issuers[serial] = issuer; algos[serial] = algo; seen[serial] = 1
        }
        sources[serial] = (sources[serial] == "" ? endpoint : sources[serial] ", " endpoint)
    }
    END {
        for (i=1; i<=count; i++) {
            s = order[i]
            printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", (cns[s]==""?"[Unknown]":cns[s]), s, (issuers[s]==""?"[Unknown]":issuers[s]), sources[s], algos[s]
        }
    }' "$TMP_FILE"
fi

rm "$TMP_FILE"

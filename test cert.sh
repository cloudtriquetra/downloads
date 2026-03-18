#!/bin/bash

# Define Host Info
HOST_FQDN=$(hostname -f)
TARGET_IP=$(hostname -I | awk '{print $1}')
TMP_FILE=$(mktemp)

# 1. STABLE DISCOVERY (No hardcoding, No container-tool dependency)
# We pull every unique port currently present in the Kernel's TCP stack
# This catches Listeners (Green) AND NAT-redirected ports (Red) 
ports=$(sudo netstat -tan | awk '{print $4}' | rev | cut -d: -f1 | rev | grep -E '^[0-9]+$' | sort -u)

for port in $ports; do
    # Skip high ephemeral ports to keep it fast
    if [ "$port" -gt 49151 ] || [ "$port" -eq 0 ]; then continue; fi

    # Probe the primary interface IP (NOT 127.0.0.1)
    # This triggers the Kernel NAT rules exactly like an external scan
    raw_cert=$(echo | timeout 2 openssl s_client -connect "$TARGET_IP":"$port" -servername "$HOST_FQDN" 2>/dev/null)

    if [[ "$raw_cert" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        clean_cert=$(echo "$raw_cert" | openssl x509)

        # Extraction logic
        cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        issuer=$(echo "$clean_cert" | openssl x509 -noout -issuer -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        
        # Identity Logic for the "Red Entry"
        if [[ "$raw_cert" == *"Fake Certificate"* ]]; then
            cn="Kubernetes Ingress Controller Fake Certificate"
            issuer="Kubernetes Ingress Controller Fake Certificate"
        fi

        # Serial Number (Preserve Colons + Uppercase)
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
            order[++count] = serial; cns[serial] = (cn==""?"[Unknown]":cn); 
            issuers[serial] = (issuer==""?"[Unknown]":issuer); algos[serial] = algo; seen[serial] = 1
        }
        sources[serial] = (sources[serial] == "" ? endpoint : sources[serial] ", " endpoint)
    }
    END {
        for (i=1; i<=count; i++) {
            s = order[i]
            printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", cns[s], s, issuers[s], sources[s], algos[s]
        }
    }' "$TMP_FILE"
fi
rm "$TMP_FILE"

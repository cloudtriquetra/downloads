#!/bin/bash

# Define Host Info
HOST_FQDN=$(hostname -f)
# Using the Primary Interface IP (10.198.25.106) found in your screenshot
TARGET_IP=$(hostname -I | awk '{print $1}')
TMP_FILE=$(mktemp)

# 1. DYNAMIC DISCOVERY (No hardcoded port lists)
# We pull ports from:
#   a) Standard Listeners (netstat)
#   b) Active NAT translations (conntrack) - This catches the "Red Entry"
#   c) Kernel IPVS rules (ipvsadm)
ports=$( ( 
    sudo netstat -tanpu | grep LISTEN | awk '{print $4}' | rev | cut -d: -f1 | rev;
    sudo conntrack -L 2>/dev/null | grep "$TARGET_IP" | grep -oE "dport=[0-9]+" | cut -d= -f2;
    sudo ipvsadm -L -n 2>/dev/null | grep -oE ":[0-9]+ " | tr -d ': ';
    sudo nft list ruleset 2>/dev/null | grep -oE "dport [0-9]+" | awk '{print $2}'
) | grep -E '^[0-9]+$' | sort -u)

for port in $ports; do
    # Skip high ephemeral ports (>49151)
    if [ "$port" -gt 49151 ] || [ "$port" -eq 0 ]; then continue; fi

    # Probe the target IP
    raw_cert=$(echo | timeout 2 openssl s_client -connect "$TARGET_IP":"$port" -servername "$HOST_FQDN" 2>/dev/null)

    if [[ "$raw_cert" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        clean_cert=$(echo "$raw_cert" | openssl x509)

        # Extraction logic
        cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        issuer=$(echo "$clean_cert" | openssl x509 -noout -issuer -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        
        # Identity Logic for the Red Entry
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

# 2. Group by Serial and Output CSV
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

if [ -s "$TMP_FILE" ]; then
    awk -F'|' '
    {
        serial=$1; cn=$2; issuer=$3; algo=$4; endpoint=$5;
        if (!(serial in seen)) {
            order[++count] = serial; cns[serial] = (cn == "" ? "[Unknown]" : cn);
            issuers[serial] = (issuer == "" ? "[Unknown]" : issuer);
            algos[serial] = algo; seen[serial] = 1
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

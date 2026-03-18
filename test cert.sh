#!/bin/bash

# 1. Setup
HOST_FQDN=$(hostname -f)
TARGET_IP=$(hostname -I | awk '{print $1}')
TMP_FILE=$(mktemp)

# 2. UNIVERSAL DISCOVERY (Multiple Layers)
# Layers: 1. Listeners, 2. NAT/iptables, 3. IPVS/LB, 4. NFTables, 5. Common Service Sweep
ports=$( ( 
    sudo netstat -tanpu | grep LISTEN | awk '{print $4}' | rev | cut -d: -f1 | rev;
    sudo iptables -t nat -L -n 2>/dev/null | grep -oE "dpt:[0-9]+" | cut -d: -f2;
    sudo nft list ruleset 2>/dev/null | grep -oE "dport [0-9]+" | awk '{print $2}';
    sudo ipvsadm -L -n 2>/dev/null | grep -oE ":[0-9]+ " | tr -d ': ';
    echo -e "80\n443\n6443\n8080\n8443"
) | grep -E '^[0-9]+$' | sort -u)

for port in $ports; do
    if [ "$port" -gt 49151 ] || [ "$port" -eq 0 ]; then continue; fi

    # Probe via External IP (Primary Interface)
    raw_cert=$(echo | timeout 2 openssl s_client -connect "$TARGET_IP":"$port" -servername "$HOST_FQDN" 2>/dev/null)

    if [[ "$raw_cert" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        clean_cert=$(echo "$raw_cert" | openssl x509)

        # Extract Fields
        cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        issuer=$(echo "$clean_cert" | openssl x509 -noout -issuer -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        
        # Handle the Red Entry (Ingress Controller)
        if [[ "$raw_cert" == *"Fake Certificate"* ]]; then
            cn="Kubernetes Ingress Controller Fake Certificate"
            issuer="Kubernetes Ingress Controller Fake Certificate"
        fi

        # Serial Number Formatting
        serial=$(echo "$clean_cert" | openssl x509 -noout -serial | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        if [[ ! "$serial" == *":"* ]]; then
            serial=$(echo "$serial" | sed 's/..\B/&:/g')
        fi
        
        algo=$(echo "$clean_cert" | openssl x509 -noout -text | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        echo "$serial|$cn|$issuer|$algo|$HOST_FQDN:$port" >> "$TMP_FILE"
    fi
done

# 3. CSV Generation with Deduping
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

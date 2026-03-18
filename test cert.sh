#!/bin/bash

# 1. Set Node context
NODE_IP=$(hostname -I | awk '{print $1}')
NODE_FQDN=$(hostname -f)

# CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# 2. Get ALL unique listening TCP ports
ports=$(sudo ss -tlnp | awk 'NR>1 {print $4}' | rev | cut -d: -f1 | rev | grep -E '^[0-9]+$' | sort -u)

for port in $ports; do
    # 3. Attempt SSL connection
    # timeout prevents hanging on non-SSL services
    cert_raw=$(timeout 2 openssl s_client -connect "$NODE_IP":"$port" -servername "$NODE_FQDN" </dev/null 2>/dev/null)

    if [[ -n "$cert_raw" ]]; then
        # 4. Use specific OpenSSL flags for high-reliability extraction
        # We extract directly to avoid parsing the full 500-line '-text' output
        
        # COMMON NAME (Subject)
        cn=$(echo "$cert_raw" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p' | xargs)
        
        # ISSUER COMMON NAME
        issuer=$(echo "$cert_raw" | openssl x509 -noout -issuer 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p' | xargs)
        
        # SERIAL NUMBER (Uppercase Hex with Colons)
        serial=$(echo "$cert_raw" | openssl x509 -noout -serial 2>/dev/null | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        # Add colons every 2 chars to match your expected photo: 31:78:54...
        if [[ -n "$serial" && ! "$serial" == *":"* ]]; then
            serial=$(echo "$serial" | sed 's/../&:/g; s/:$//')
        fi

        # SIGNATURE ALGORITHM
        algo=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        # 5. Output Result if a Serial was found
        if [[ -n "$serial" ]]; then
            echo "${cn:-[Unknown]},$serial,${issuer:-[Unknown]},$NODE_FQDN:$port,${algo:-[Unknown]}"
        fi
    fi
done

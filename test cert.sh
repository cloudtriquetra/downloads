#!/bin/bash

# Get Host Info
HOST_FQDN=$(hostname -f)
HOST_IP=$(hostname -I | awk '{print $1}')

# Print CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# Identify ports from netstat (including container-forwarded ports like 8080/8443)
ports=$(sudo netstat -tanpu | grep -E 'LISTEN|:8080|:8443' | awk '{print $4}' | rev | cut -d: -f1 | rev | grep -E '^[0-9]+$' | sort -u)

for port in $ports; do
    # Try connecting using the FQDN first (best for SNI/K8s), then fall back to IP
    raw_info=$(timeout 2 openssl s_client -connect "$HOST_IP":"$port" -servername "$HOST_FQDN" </dev/null 2>/dev/null)

    if [ -n "$raw_info" ]; then
        # Parse certificate using openssl x509
        cert_text=$(echo "$raw_info" | openssl x509 -noout -text 2>/dev/null)
        
        if [ -n "$cert_text" ]; then
            # 1. Common Name: Look for CN= and grab until comma or EOL
            cn=$(echo "$cert_text" | grep "Subject:" | sed -n 's/.*CN = //p' | cut -d',' -f1 | xargs)
            # Fallback if CN is missing (common in some K8s certs)
            [[ -z "$cn" ]] && cn=$(echo "$cert_text" | grep "Subject:" | awk -F'=' '{print $NF}' | xargs)

            # 2. Serial Number: Get hex, remove colons, uppercase
            serial=$(echo "$cert_text" | grep -A1 "Serial Number:" | tail -n1 | xargs | tr -d ':' | tr '[:lower:]' '[:upper:]')

            # 3. Issuer Common Name: Specifically targeting the CN in the Issuer field
            issuer=$(echo "$cert_text" | grep "Issuer:" | sed -n 's/.*CN = //p' | cut -d',' -f1 | xargs)
            # Fallback for Issuer
            [[ -z "$issuer" ]] && issuer=$(echo "$cert_text" | grep "Issuer:" | awk -F'=' '{print $NF}' | xargs)

            # 4. Discovery Source: Format matches your 1st photo (FQDN:Port)
            discovery="$HOST_FQDN:$port"

            # 5. Signature Algorithm
            algo=$(echo "$cert_text" | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

            echo "${cn:-[Unknown]},${serial:-[N/A]},${issuer:-[Unknown]},$discovery,$algo"
        fi
    fi
done

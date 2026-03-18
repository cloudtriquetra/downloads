#!/bin/bash

# Define Host Info
HOST_FQDN=$(hostname -f)
HOST_IP=$(hostname -I | awk '{print $1}')

# Print CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# Identify ports
ports=$(sudo netstat -tanpu | grep -E 'LISTEN|:8080|:8443' | awk '{print $4}' | rev | cut -d: -f1 | rev | grep -E '^[0-9]+$' | sort -u)

for port in $ports; do
    # Connect and grab the certificate
    raw_cert=$(echo | timeout 3 openssl s_client -connect "$HOST_IP":"$port" -servername "$HOST_FQDN" 2>/dev/null)

    if [[ "$raw_cert" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        # Extract the cert block for parsing
        clean_cert=$(echo "$raw_cert" | openssl x509)

        # 1. Common Name - Using a simpler AWK split to avoid [Unknown]
        cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        
        # 2. Serial Number - PRESERVING COLONS and forcing Uppercase
        serial=$(echo "$clean_cert" | openssl x509 -noout -serial | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        
        # 3. Issuer Common Name
        issuer=$(echo "$clean_cert" | openssl x509 -noout -issuer -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        
        # 4. Discovery Source
        discovery="$HOST_FQDN:$port"
        
        # 5. Signature Algorithm
        algo=$(echo "$clean_cert" | openssl x509 -noout -text | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        # Handle the "Fake Certificate" string specifically for your report
        if [[ "$raw_cert" == *"Fake Certificate"* ]]; then
            cn="Kubernetes Ingress Controller Fake Certificate"
            issuer="Kubernetes Ingress Controller Fake Certificate"
        fi

        # Final check: if CN is empty, use the Serial Number as a fallback for the row
        if [[ -n "$serial" ]]; then
            echo "${cn:-[Unknown]},$serial,${issuer:-[Unknown]},$discovery,$algo"
        fi
    fi
done

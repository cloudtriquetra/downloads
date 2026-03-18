#!/bin/bash

# 1. Dynamic Environment Detection
HOST_FQDN=$(hostname -f)
HOST_IP=$(hostname -I | awk '{print $1}')

echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# 2. Generic Port Discovery
# This finds ALL unique ports that are:
# - LISTEN (Standard servers)
# - ESTABLISHED/TIME_WAIT (K8s/Containerized forwarding)
# We exclude common non-SSL ports like 22 (SSH) to speed it up.
ports=$(sudo netstat -tanpu | awk '{print $4}' | grep -oE '[0-9]+$' | grep -vE '^(22|111)$' | sort -u)

for port in $ports; do
    # 3. The "Knock" - Try to see if it's an SSL/TLS port
    # We use a 2-second timeout to keep the script fast on non-SSL ports
    raw_cert=$(echo | timeout 2 openssl s_client -connect "$HOST_IP":"$port" -servername "$HOST_FQDN" 2>/dev/null)

    # 4. Process only if a certificate is actually found
    if [[ "$raw_cert" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        
        # Extract the cert into a variable to avoid "stdin" errors
        clean_cert=$(echo "$raw_cert" | openssl x509)

        # Robust Parsing
        cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\([^,]*\).*/\1/p' | xargs)
        issuer=$(echo "$clean_cert" | openssl x509 -noout -issuer -nameopt RFC2253 | sed -n 's/.*CN=\([^,]*\).*/\1/p' | xargs)
        serial=$(echo "$clean_cert" | openssl x509 -noout -serial | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        algo=$(echo "$clean_cert" | openssl x509 -noout -text | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        # 5. Generic "Fake/Internal" Labeling
        # Handles K8s ingress, but also generic self-signed or internal CA's
        if [[ "$raw_cert" == *"Fake Certificate"* ]]; then
            cn="Kubernetes Ingress Controller Fake Certificate"
            issuer="Kubernetes Ingress Controller Fake Certificate"
        fi

        # If CN is still empty (some system certs), use the full Subject path
        [[ -z "$cn" ]] && cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | awk -F'=' '{print $NF}')

        echo "${cn:-[Unknown]},$serial,${issuer:-[Unknown]},$HOST_FQDN:$port,$algo"
    fi
done | sort -u

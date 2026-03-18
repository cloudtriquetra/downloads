#!/bin/bash

# Get Host Info
HOST_FQDN=$(hostname -f)
HOST_IP=$(hostname -I | awk '{print $1}')

# Print CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# 1. Get EVERY unique local port currently active on the system
# This catches Ingress (443), Pixee (8080), and K8s internals (10250)
all_ports=$(sudo netstat -tan | awk '{print $4}' | rev | cut -d: -f1 | rev | grep -E '^[0-9]+$' | sort -u)

for port in $all_ports; do
    # Skip extremely high ephemeral ports to save time (>49151)
    if [ "$port" -gt 49151 ]; then continue; fi

    # 2. Try to grab the certificate
    # We use -servername to ensure SNI works for the Ingress 'Fake' certs
    raw_cert=$(echo | timeout 2 openssl s_client -connect "$HOST_IP":"$port" -servername "$HOST_FQDN" 2>/dev/null)

    # 3. Only proceed if the port actually returned a TLS certificate
    if [[ "$raw_cert" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        clean_cert=$(echo "$raw_cert" | openssl x509)

        # Extract Fields (Preserving Colons in Serial)
        cn=$(echo "$clean_cert" | openssl x509 -noout -subject -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        serial=$(echo "$clean_cert" | openssl x509 -noout -serial | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        issuer=$(echo "$clean_cert" | openssl x509 -noout -issuer -nameopt RFC2253 | awk -F'CN=' '{print $2}' | cut -d',' -f1 | xargs)
        algo=$(echo "$clean_cert" | openssl x509 -noout -text | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        # 4. Handle "Fake Certificate" naming to match your expected red row
        if [[ "$raw_cert" == *"Fake Certificate"* ]]; then
            cn="Kubernetes Ingress Controller Fake Certificate"
            issuer="Kubernetes Ingress Controller Fake Certificate"
        fi

        # 5. Handle rows where CN might be an IP or hostname (like 10.198.25.106)
        if [[ -z "$cn" ]]; then
            cn=$(echo "$clean_cert" | openssl x509 -noout -subject | awk -F'=' '{print $NF}' | xargs)
        fi

        echo "${cn:-[Unknown]},$serial,${issuer:-[Unknown]},$HOST_FQDN:$port,$algo"
    fi
done | sort -u

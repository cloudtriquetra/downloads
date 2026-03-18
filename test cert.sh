#!/bin/bash

# Get the host's FQDN
HOSTNAME=$(hostname -f)

# Print the CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# Find all unique ports that are either listening or active
# This handles the 'hidden' container ports seen in your netstat screenshot
ports=$(netstat -ant | grep -E 'LISTEN|:8080|:8443' | awk '{print $4}' | awk -F: '{print $NF}' | grep -v '^$' | sort -u)

for port in $ports; do
    # Connect and pull the certificate
    # We use -servername with the hostname to ensure we get the right SNI cert
    raw_cert=$(timeout 2 openssl s_client -connect 127.0.0.1:"$port" -servername "$HOSTNAME" </dev/null 2>/dev/null)
    
    if [ -n "$raw_cert" ]; then
        # Parse the details using openssl x509
        cert_info=$(echo "$raw_cert" | openssl x509 -noout -text 2>/dev/null)
        
        if [ -n "$cert_info" ]; then
            # 1. Common Name (CN)
            cn=$(echo "$cert_info" | grep "Subject:" | sed -n 's/.*CN = //p' | cut -d',' -f1 | xargs)
            
            # 2. Serial Number (Format: hex string without colons)
            serial=$(echo "$cert_info" | grep -A1 "Serial Number:" | tail -n1 | xargs | tr -d ':' | tr '[:lower:]' '[:upper:]')
            
            # 3. Issuer Common Name
            issuer=$(echo "$cert_info" | grep "Issuer:" | sed -n 's/.*CN = //p' | cut -d',' -f1 | xargs)
            
            # 4. Discovery Source (Formatted as FQDN:PORT)
            discovery="$HOSTNAME:$port"
            
            # 5. Signature Algorithm
            algo=$(echo "$cert_info" | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

            # Output as CSV row
            echo "${cn:-[Unknown]},${serial:-[N/A]},${issuer:-[Unknown]},$discovery,$algo"
        fi
    fi
done

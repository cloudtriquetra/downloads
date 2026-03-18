#!/bin/bash

# Print the CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# Get all listening ports AND the specific IP they are bound to
# This avoids the 127.0.0.1 connection issue
netstat -tunlp | grep LISTEN | awk '{print $4}' | while read -r line; do
    ip=$(echo "$line" | awk -F: '{print $(NF-1)}')
    port=$(echo "$line" | awk -F: '{print $NF}')

    # If IP is 0.0.0.0 (all interfaces), use the primary host IP or localhost
    [[ -z "$ip" || "$ip" == "0.0.0.0" || "$ip" == "*" ]] && target_ip="127.0.0.1" || target_ip="$ip"

    # Attempt to pull certificate
    # Added -fallback_scsv to be more compatible with different TLS versions
    cert_raw=$(timeout 2 openssl s_client -connect "$target_ip":"$port" -servername "$target_ip" </dev/null 2>/dev/null)
    
    if [ -n "$cert_raw" ]; then
        cert_info=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null)
        
        if [ -n "$cert_info" ]; then
            cn=$(echo "$cert_info" | sed -n 's/.*Subject:.*CN = //p' | cut -d',' -f1 | xargs)
            serial=$(echo "$cert_info" | grep -A1 "Serial Number:" | tail -n1 | xargs | tr -d ':' | tr '[:lower:]' '[:upper:]')
            issuer=$(echo "$cert_info" | sed -n 's/.*Issuer:.*CN = //p' | cut -d',' -f1 | xargs)
            algo=$(echo "$cert_info" | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)
            
            # Use [Unknown] only if the field is truly empty
            echo "${cn:-[Unknown]},${serial:-[N/A]},${issuer:-[Unknown]},$(hostname):$port,$algo"
        fi
    fi
done

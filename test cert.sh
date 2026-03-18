#!/bin/bash

# Get all unique listening TCP ports
ports=$(ss -tunlp | awk 'NR>1 {print $5}' | cut -d':' -f2 | sort -u)

echo -e "Port\tCommon Name\t\t\tExpiry Date"
echo -e "------------------------------------------------------------"

for port in $ports; do
    # Attempt to pull certificate info using openssl
    # timeout 2 ensures we don't hang on non-SSL ports
    cert_info=$(timeout 2 openssl s_client -connect 127.0.0.1:"$port" -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate 2>/dev/null)

    if [ -n "$cert_info" ]; then
        # Parse the CN and the Expiry Date
        cn=$(echo "$cert_info" | grep "subject" | sed -n 's/.*CN = //p')
        expiry=$(echo "$cert_info" | grep "notAfter" | cut -d'=' -f2)
        
        printf "%-8s %-30s %s\n" "$port" "${cn:-[Unknown]}" "$expiry"
    else
        # Optional: Print ports that are open but have no SSL/TLS
        printf "%-8s [No SSL/TLS detected]\n" "$port"
    fi
done

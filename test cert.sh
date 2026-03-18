#!/bin/bash

# 1. Identify Host IP for connection
HOST_IP=$(hostname -I | awk '{print $1}')

# Print CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# 2. Get Ports (Simplified to ensure we catch everything)
# We take the 4th column, split by ':' and take the last part (the port)
ports=$(sudo netstat -tanpu | grep -E 'LISTEN|:8080|:8443' | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u)

for port in $ports; do
    # Skip empty lines or non-numeric ports
    [[ ! "$port" =~ ^[0-9]+$ ]] && continue

    # 3. Attempt connection - specifically using the Host IP
    # Redirecting ALL output to a variable to check if it's empty
    raw_output=$(timeout 2 openssl s_client -connect "$HOST_IP":"$port" -servername "$HOST_IP" </dev/null 2>/dev/null)

    if [ -n "$raw_output" ]; then
        # 4. Extracting data using the most direct OpenSSL flags
        # These flags (-subject, -issuer, -serial) are much more reliable than 'grep' on the full text
        cn=$(echo "$raw_output" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p' | xargs)
        
        # If CN is still empty, try to get it from the full Subject line as a fallback
        [[ -z "$cn" ]] && cn=$(echo "$raw_output" | openssl x509 -noout -subject 2>/dev/null | awk -F'=' '{print $NF}' | xargs)

        serial=$(echo "$raw_output" | openssl x509 -noout -serial 2>/dev/null | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')
        issuer=$(echo "$raw_output" | openssl x509 -noout -issuer 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p' | xargs)
        algo=$(echo "$raw_output" | openssl x509 -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        # Only print if we actually found a certificate (prevents blank rows for non-SSL ports)
        if [ -n "$cn" ] || [ -n "$serial" ]; then
            echo "${cn:-[Unknown]},${serial:-[N/A]},${issuer:-[Unknown]},$(hostname):$port,${algo:-[Unknown]}"
        fi
    fi
done            continue
        fi
    fi
done

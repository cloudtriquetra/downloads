#!/bin/bash

# Get the host's IP and FQDN
HOST_IP=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname -f)

# Print the CSV Header
echo "Common name,Serial number,Issuer common name,Discovery source,Signature Algorithm"

# Get unique listening ports
ports=$(netstat -tulnp | grep LISTEN | awk '{print $4}' | awk -F: '{print $NF}' | sort -u)

for port in $ports; do
    # 1. Capture the raw certificate data
    # We try connecting to the specific Host IP first, then 127.0.0.1
    cert_raw=$(timeout 2 openssl s_client -connect "$HOST_IP":"$port" -servername "$HOSTNAME" </dev/null 2>/dev/null)

    if [ -n "$cert_raw" ]; then
        # 2. Extract Common Name using a more reliable sed pattern
        # This looks for 'CN =' and grabs everything until the next comma or end of line
        cn=$(echo "$cert_raw" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p' | xargs)

        # 3. Extract Serial Number (Hex format, no colons, Uppercase)
        serial=$(echo "$cert_raw" | openssl x509 -noout -serial 2>/dev/null | cut -d'=' -f2 | tr '[:lower:]' '[:upper:]')

        # 4. Extract Issuer Common Name
        issuer=$(echo "$cert_raw" | openssl x509 -noout -issuer 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p' | xargs)

        # 5. Extract Signature Algorithm
        algo=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)

        # Only output if we actually found a certificate
        if [ -n "$cn" ]; then
            echo "$cn,$serial,$issuer,$HOSTNAME:$port,$algo"
        else
            # If CN is still empty, the port might be open but not SSL/TLS
            continue
        fi
    fi
done

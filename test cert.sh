#!/bin/bash

# 1. Identify all ports that are either LISTENING or have active 8080 traffic
# We use 'sort -u' to ensure we only check each unique port once.
ports=$(netstat -an | grep -E 'LISTEN|:8080' | awk '{print $4}' | awk -F: '{print $NF}' | grep -v '^$' | sort -u)

echo -e "\n%-8s %-25s %-30s" "PORT" "SIGNATURE ALGORITHM" "COMMON NAME (CN)"
echo "--------------------------------------------------------------------------"

for port in $ports; do
    # 2. Extract cert info. We specifically grab the 'Signature Algorithm' line.
    # timeout 2 prevents hanging on non-SSL ports.
    cert_data=$(timeout 2 openssl s_client -connect 127.0.0.1:"$port" -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -text 2>/dev/null)

    if [ -n "$cert_data" ]; then
        algo=$(echo "$cert_data" | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)
        cn=$(echo "$cert_data" | grep "Subject:" | sed -n 's/.*CN = //p' | cut -d',' -f1)
        
        # 3. Validation Logic (Example: flagging weak SHA1)
        if [[ "$algo" == *"sha1"* ]]; then
            algo="$algo [WEAK!]"
        fi

        printf "%-8s %-25s %-30s\n" "$port" "$algo" "${cn:-[Unknown]}"
    else
        # Skip or report ports with no SSL
        continue
    fi
done
echo -e "--------------------------------------------------------------------------\n"

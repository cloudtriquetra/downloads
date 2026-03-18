#!/bin/bash

# 1. Identify all listening or active ports (including container-forwarded ones)
ports=$(netstat -tuln | awk 'NR>2 {print $4}' | awk -F: '{print $NF}' | grep -v '^$' | sort -u)

echo -e "\n%-8s %-25s %-30s %-40s" "PORT" "ALGORITHM" "COMMON NAME (CN)" "SAN / FQDNs"
echo "------------------------------------------------------------------------------------------------------------------------"

for port in $ports; do
    # 2. Extract full cert text
    cert_data=$(timeout 2 openssl s_client -connect 127.0.0.1:"$port" -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -text 2>/dev/null)

    if [ -n "$cert_data" ]; then
        # Extract Algorithm
        algo=$(echo "$cert_data" | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)
        
        # Extract Common Name (CN)
        cn=$(echo "$cert_data" | grep "Subject:" | sed -n 's/.*CN = //p' | cut -d',' -f1 | xargs)
        
        # Extract SANs (Subject Alternative Names) - this is where FQDNs usually live
        sans=$(echo "$cert_data" | sed -n '/X509v3 Subject Alternative Name/{n;p}' | xargs | sed 's/DNS://g')

        # Simple validation: Mark SHA1 or MD5 as weak
        if [[ "$algo" == *"sha1"* || "$algo" == *"md5"* ]]; then
            algo="$algo (!)"
        fi

        printf "%-8s %-25s %-30s %-40s\n" "$port" "$algo" "${cn:-[None]}" "${sans:-[None]}"
    fi
done
echo -e "------------------------------------------------------------------------------------------------------------------------\n"

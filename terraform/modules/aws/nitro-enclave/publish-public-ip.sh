
# --- Deployments lifecycle, enclave TLS: publish this instance's public IPv4 ---
# The enclave resolves public-ipv4.caution.internal through this host's
# dnsmasq and starts Caddy once the app domain resolves to the same address:
# that holds only while this deployment holds the app's Elastic IP.
cat > /usr/local/bin/caution-publish-public-ip.sh <<'PUBLISH'
#!/bin/bash
NAME=public-ipv4.caution.internal
while :; do
    TOKEN=$(curl -s --connect-timeout 2 --max-time 5 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
    IP=$(curl -s --connect-timeout 2 --max-time 5 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
    [[ "$IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || IP=""
    CURRENT=$(awk -v name="$NAME" '$2 == name { print $1 }' /etc/hosts)
    if [ "$IP" != "$CURRENT" ]; then
        { grep -v " $NAME\$" /etc/hosts; [ -n "$IP" ] && echo "$IP $NAME"; } > /etc/hosts.caution
        cat /etc/hosts.caution > /etc/hosts
        pkill -HUP -x dnsmasq || true
    fi
    sleep 15
done
PUBLISH
chmod +x /usr/local/bin/caution-publish-public-ip.sh
cat > /etc/systemd/system/caution-public-ip.service <<'EOF'
[Unit]
Description=Publish this instance's public IPv4 to the enclave
After=vsock-network.service

[Service]
ExecStart=/usr/local/bin/caution-publish-public-ip.sh
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now caution-public-ip.service

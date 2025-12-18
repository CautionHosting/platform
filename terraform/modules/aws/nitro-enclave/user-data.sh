#!/bin/bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "=== Nitro Enclave Setup ==="
echo "Starting at $(date)"

echo "Installing required packages..."
dnf update -y
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat dnsmasq iptables iproute

%{ if length(ssh_keys) > 0 ~}
echo "Adding SSH keys to authorized_keys..."
mkdir -p /home/ec2-user/.ssh
chmod 700 /home/ec2-user/.ssh
%{ for key in ssh_keys ~}
echo "${key}" >> /home/ec2-user/.ssh/authorized_keys
%{ endfor ~}
chmod 600 /home/ec2-user/.ssh/authorized_keys
chown -R ec2-user:ec2-user /home/ec2-user/.ssh
echo "Added ${length(ssh_keys)} SSH key(s)"
%{ endif ~}

systemctl start docker
systemctl enable docker

systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service

echo "Configuring Nitro Enclaves allocator..."
systemctl stop nitro-enclaves-allocator.service

cat > /etc/nitro_enclaves/allocator.yaml <<EOF
---
memory_mib: ${memory_mb}
cpu_count: ${cpu_count}
EOF

echo "Restarting allocator with ${memory_mb} MiB memory and ${cpu_count} CPUs..."
systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service

sleep 2

mkdir -p /opt/nitro

echo "Downloading EIF from ${eif_s3_path}..."
aws s3 cp "${eif_s3_path}" /opt/nitro/enclave.eif

echo "Setting up vsock network proxy for enclave..."
cat > /usr/local/bin/vsock-network-proxy.sh <<'PROXY_SCRIPT'
#!/bin/bash
set -e

echo "Starting vsock network proxy..."

echo 1 > /proc/sys/net/ipv4/ip_forward

ip tuntap add mode tap name enclave0
ip addr add 10.0.100.1/24 dev enclave0
ip link set enclave0 up

socat TUN,tun-type=tap,iff-no-pi,tun-name=enclave0 VSOCK-LISTEN:3,fork,reuseaddr &
SOCAT_PID=$!
echo "VSock bridge started (PID: $SOCAT_PID)"

iptables -t nat -A POSTROUTING -s 10.0.100.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i enclave0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o enclave0 -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "NAT rules configured"

dnsmasq \
  --interface=enclave0 \
  --bind-interfaces \
  --dhcp-range=10.0.100.10,10.0.100.50,12h \
  --dhcp-option=3,10.0.100.1 \
  --dhcp-option=6,10.0.100.1 \
  --no-daemon \
  --log-queries \
  --log-dhcp &

DNSMASQ_PID=$!
echo "DHCP/DNS server started (PID: $DNSMASQ_PID)"

wait
PROXY_SCRIPT

chmod +x /usr/local/bin/vsock-network-proxy.sh

cat > /etc/systemd/system/vsock-network.service <<'EOF'
[Unit]
Description=VSock Network Proxy for Enclave
After=network.target
Before=nitro-enclave.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vsock-network-proxy.sh
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vsock-network.service
systemctl start vsock-network.service

sleep 3

cat > /etc/systemd/system/nitro-enclave.service <<EOF
[Unit]
Description=Nitro Enclave Application
After=nitro-enclaves-allocator.service
Requires=nitro-enclaves-allocator.service

[Service]
Type=simple
ExecStartPre=/bin/sleep 2
ExecStart=/bin/bash -c 'nitro-cli run-enclave --eif-path /opt/nitro/enclave.eif --memory ${memory_mb} --cpu-count ${cpu_count} --enclave-cid 16 %{if debug_mode == "true"}--debug-mode%{endif} && tail -f /dev/null'
ExecStop=/usr/bin/nitro-cli terminate-enclave --all
Restart=on-failure
RestartSec=10s
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

# Attestation port (always 5000)
cat > /etc/systemd/system/vsock-proxy-5000.service <<'EOF'
[Unit]
Description=VSock Proxy for Attestation Port 5000
After=nitro-enclave.service
Requires=nitro-enclave.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:5000,reuseaddr,fork VSOCK-CONNECT:16:5000
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Dynamic user ports
%{ for port in ports ~}
cat > /etc/systemd/system/vsock-proxy-${port}.service <<EOF
[Unit]
Description=VSock Proxy for Port ${port}
After=nitro-enclave.service
Requires=nitro-enclave.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:${port},reuseaddr,fork VSOCK-CONNECT:16:${port}
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
%{ endfor ~}

systemctl daemon-reload
systemctl enable nitro-enclave.service
systemctl enable vsock-proxy-5000.service
%{ for port in ports ~}
systemctl enable vsock-proxy-${port}.service
%{ endfor ~}

systemctl start nitro-enclave.service

# Wait for enclave to boot and start internal services before starting host-side proxies
echo "Waiting for enclave to boot before starting host-side proxies..."
sleep 15

systemctl start vsock-proxy-5000.service
%{ for port in ports ~}
systemctl start vsock-proxy-${port}.service
%{ endfor ~}

echo "=== Nitro Enclave Setup Complete ==="
echo "Finished at $(date)"

echo "=== Attempting to read enclave console (early capture) ==="
echo "Waiting 5 seconds for enclave to boot..."
sleep 5

for i in {1..3}; do
  ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | grep -o '"EnclaveID": "[^"]*"' | cut -d'"' -f4 | head -1)
  if [ -n "$ENCLAVE_ID" ]; then
    echo "Found enclave ID on attempt $i: $ENCLAVE_ID"
    break
  fi
  echo "Attempt $i: No enclave ID yet, retrying..."
  sleep 1
done

if [ -n "$ENCLAVE_ID" ]; then
  echo "Enclave is running, capturing console output:"
  echo "=========================================="
  timeout 10 nitro-cli console --enclave-id "$ENCLAVE_ID" 2>&1 || echo "Console read failed or timed out"
  echo "=========================================="
else
  echo "ERROR: No enclave ID found after 3 attempts - enclave likely crashed immediately"
  echo "Checking for any error messages in nitro-cli logs..."
  journalctl -u nitro-enclave.service --no-pager || true
fi

sleep 7
echo "=== Checking Service Status ==="
echo "Allocator service:"
systemctl status nitro-enclaves-allocator.service --no-pager || true
echo ""
echo "Enclave service:"
systemctl status nitro-enclave.service --no-pager || true
echo ""
echo "Running enclaves:"
nitro-cli describe-enclaves || echo "No enclaves running or command failed"
echo ""
echo "Recent enclave service logs:"
journalctl -u nitro-enclave.service -n 50 --no-pager || true
echo "=== End Status Check ==="

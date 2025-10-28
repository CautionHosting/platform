#!/bin/sh
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

echo "=== Caution Enclave Startup ==="

echo "Setting up network loopback..."
/bin/busybox ip addr add 127.0.0.1/8 dev lo
/bin/busybox ip link set dev lo up
/bin/busybox ip link show lo

echo "127.0.0.1   localhost" > /etc/hosts

echo "Network loopback configured"

echo "Setting up vsock network tunnel to parent..."
# Connect to parent's network proxy via vsock port 3
# This creates a virtual ethernet interface (eth0) connected to the parent
/bin/socat TUN,tun-type=tap,iff-no-pi,iff-up,tun-name=eth0 VSOCK-CONNECT:3:3 &
SOCAT_PID=$!
echo "VSock tunnel started (PID: $SOCAT_PID)"

# Wait for interface to come up
/bin/busybox sleep 2

# Verify eth0 exists
if /bin/busybox ip link show eth0 2>/dev/null; then
    echo "eth0 interface created successfully"

    # Get IP address via DHCP from parent
    echo "Requesting IP via DHCP..."
    /bin/busybox udhcpc -i eth0 -s /bin/udhcpc-script -q

    # Show network configuration
    echo "Network configuration:"
    /bin/busybox ip addr show eth0
    /bin/busybox ip route show

    # Update resolv.conf with DNS from parent (10.0.100.1)
    echo "nameserver 10.0.100.1" > /etc/resolv.conf

    echo "Network tunnel established successfully"
else
    echo "WARNING: Failed to create eth0 interface, running without internet access"
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
fi

echo "Loading NSM kernel module..."
if [ -f /nsm.ko ]; then
    insmod /nsm.ko && echo "NSM module loaded successfully" || echo "Failed to load NSM module"
else
    echo "WARNING: NSM module not found at /nsm.ko"
fi

export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

echo "Starting Attestation Service on port 5000..."
/attestation-service &

echo "Starting VSOCK-to-TCP proxies..."
/bin/socat VSOCK-LISTEN:5000,reuseaddr,fork TCP:localhost:5000 &
/bin/socat VSOCK-LISTEN:8080,reuseaddr,fork TCP:localhost:8080 &

/bin/busybox sleep 2

echo "Looking for user application in /app..."
cd /app || exit 1

echo "Contents of /app:"
/bin/busybox ls -la /app || echo "Could not list /app"

for exe in $(/bin/busybox find /app -type f -executable 2>/dev/null); do
    echo "Executing: $exe"
    exec "$exe"
done

echo "ERROR: No executable found in /app"
exit 1

#!/bin/sh
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# udhcpc script for busybox DHCP client
# Called by udhcpc with environment variables containing DHCP config

case "$1" in
    deconfig)
        # Deconfigure interface
        /bin/busybox ip addr flush dev $interface
        /bin/busybox ip link set $interface up
        ;;

    renew|bound)
        # Configure IP address
        /bin/busybox ip addr add $ip/$mask dev $interface

        # Configure default route
        if [ -n "$router" ]; then
            /bin/busybox ip route add default via $router dev $interface
        fi

        # Configure DNS
        if [ -n "$dns" ]; then
            echo -n > /etc/resolv.conf
            for i in $dns; do
                echo "nameserver $i" >> /etc/resolv.conf
            done
        fi
        ;;
esac

exit 0

#!/bin/sh

CONFIG_PATH=/etc/frontman/frontman.conf

if [ "$1" = configure ]; then
    # $2 contains previous version number
    if [ -z "$2" ]; then # fresh install
        /usr/bin/frontman -y -s frontman -c ${CONFIG_PATH}
    else # package update
        serviceStatus=`/usr/bin/frontman -y -service_status -c ${CONFIG_PATH}`
        echo "current service status: $serviceStatus."

        if [ "$serviceStatus" != stopped ]; then
            echo "stopping service..."
            /usr/bin/frontman -service_stop || true
        fi

        echo "upgrading service unit... "
        /usr/bin/frontman -y -s frontman -service_upgrade -c ${CONFIG_PATH}

        # restart only if it was active before
        if [ "$serviceStatus" != stopped ]; then
            echo "restarting service... "
            /usr/bin/frontman -y -service_restart -c ${CONFIG_PATH}
        fi
    fi
fi

/usr/bin/frontman -t || true

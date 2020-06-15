#!/bin/sh

CONFIG_PATH=/etc/frontman/frontman.conf

# Install the first time:	1
# Upgrade: 2 or higher (depending on the number of versions installed)
versionsCount=$1

# install selinux policy
if [ -e /usr/sbin/semodule ]; then
    echo "Installing SELinux policy for frontman"
    checkmodule -M -m -o frontman.mod frontman.tt
    semodule_package -o frontman.pp -m frontman.mod
    semodule -i frontman.pp
fi

if [ ${versionsCount} = 1 ]; then # fresh install
    /usr/bin/frontman -y -s frontman -c ${CONFIG_PATH}
else # package update
    serviceStatus=`/usr/bin/frontman -y -service_status -c ${CONFIG_PATH}`
    echo "current service status: $serviceStatus."

    case "$serviceStatus" in
        unknown|failed)
            echo "trying to repair service..."
            /usr/bin/frontman -u || true
            /usr/bin/frontman -y -s frontman -c ${CONFIG_PATH}
            ;;

        running|stopped)
            # try to upgrade service unit config

            if [ "$serviceStatus" = running ]; then
                echo "stopping service..."
                /usr/bin/frontman -service_stop || true
            fi

            echo "upgrading service unit... "
            /usr/bin/frontman -y -s frontman -service_upgrade -c ${CONFIG_PATH}

            # restart only if it was active before
            if [ "$serviceStatus" = running ]; then
                echo "starting service... "
                /usr/bin/frontman -y -service_start -c ${CONFIG_PATH}
            fi
            ;;

        *)
            echo "unknown service status. Exiting..."
            exit 1
            ;;
    esac
fi

/usr/bin/frontman -t || true

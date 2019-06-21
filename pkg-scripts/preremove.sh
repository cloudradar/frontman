#!/bin/sh

case "$1" in
    remove)
        # remove service only when removing package (not update)
        /usr/bin/frontman -u
        ;;
    upgrade)
        # do not stop service on package upgrade because it will be restarted by new package' postinst script
        ;;
    *)
        echo "stopping service..."
        /usr/bin/frontman -service_stop || true
        ;;
esac

exit 0
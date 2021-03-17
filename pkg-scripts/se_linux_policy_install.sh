#!/bin/sh

echo "Installing SELinux policy for frontman"
checkmodule -M -m -o frontman.mod /etc/frontman/frontman.tt
semodule_package -o frontman.pp -m frontman.mod
semodule -i frontman.pp

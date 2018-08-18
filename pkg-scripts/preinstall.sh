#!/bin/sh

# check that owner group exists
if [ -z `getent group frontman` ]; then
  groupadd frontman
fi

# check that user exists
if [ -z `getent passwd frontman` ]; then
  useradd  --gid frontman --system --shell /bin/false frontman
fi

sysctl -w net.ipv4.ping_group_range="0   2147483647"
echo "net.ipv4.ping_group_range = 0 2147483647" > /usr/lib/sysctl.d/50-ping_group_range.conf
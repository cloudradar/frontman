#!/bin/sh

# check that owner group exists
if [ -z `getent group frontman` ]; then
  groupadd frontman
fi

# check that user exists
if [ -z `getent passwd frontman` ]; then
  useradd  --gid frontman --system --shell /bin/false frontman
fi

# remove deprecated sysctl setting
test -e /etc/sysctl.d/50-ping_group_range.conf && rm -f /etc/sysctl.d/50-ping_group_range.conf

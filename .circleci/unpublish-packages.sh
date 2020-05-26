#!/usr/bin/env bash

set -xe

ssh_cr() {
  ssh -p 24480 -oStrictHostKeyChecking=no cr@repo.cloudradar.io "$@"
}

ssh_cr /home/cr/work/msi/feed_delete.sh frontman rolling ${CIRCLE_TAG}
ssh_cr /home/cr/work/msi/feed_delete.sh frontman stable ${CIRCLE_TAG}

github-release delete --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG}



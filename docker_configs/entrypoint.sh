#!/bin/sh
# Get current ip and execute clair-scanner

CURRENT_IP=$(ip -o -4 addr list | head -n2 | grep -v '127.0.0.1' | awk '{print $4}' | awk -F '/' '{print $1}')
/bin/clair-scanner --ip ${CURRENT_IP} $*

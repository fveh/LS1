#!/bin/sh

# Secure environment setup
export PYTHONUNBUFFERED=1
export PYTHONPATH=/liberty
umask 077

# Anti-forensic cleanup
find /tmp -type f -exec shred -zu {} \;
rm -rf /tmp/* /var/tmp/*

# Execute with encrypted config
exec python3 /liberty/LibertyShield_Full.py \
    --config /config/opconfig.enc \
    --keyfile /secrets/master.key

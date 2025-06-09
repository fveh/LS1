#!/bin/bash
# Deployment script for air-gapped systems

# Generate keys
openssl rand -hex 32 > master.key
openssl rand -hex 16 > aes_seed.bin

# Build Docker container
docker build -t libertyshield:v4 .

# Create secure volume
docker volume create liberty_config

# Initialize container
docker run -it --rm \
  -v liberty_config:/config \
  -v $(pwd):/secrets:ro \
  libertyshield:v4 \
  python3 /liberty/LibertyShield_Full.py \
    --gen-config /config/opconfig.enc \
    --keyfile /secrets/master.key \
    --aes-seed /secrets/aes_seed.bin

# Generate keys
./deploy.sh

# Launch attack (air-gapped)
docker run -d --rm \
  --network host \
  -v liberty_config:/config:ro \
  libertyshield:v4

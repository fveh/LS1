FROM alpine:edge

RUN apk add --no-cache python3 py3-pip build-base python3-dev libffi-dev openssl-dev
RUN pip3 install --no-cache-dir pycryptodome numpy

# Install scapy for raw packet manipulation
RUN pip3 install --no-cache-dir scapy

WORKDIR /liberty
COPY LibertyShield_Full.py .
COPY entrypoint.sh .

# Stealth setup
RUN rm -rf /var/cache/apk/* /tmp/*
RUN adduser -D -u 1000 libertyuser

USER libertyuser
ENTRYPOINT ["./entrypoint.sh"]

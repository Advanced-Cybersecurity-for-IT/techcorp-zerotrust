# Real IPTables Firewall Container
# Uses actual iptables for network-level packet filtering

FROM alpine:3.19

# Install iptables, networking tools, and Python for status API
RUN apk add --no-cache \
    iptables \
    ip6tables \
    python3 \
    curl \
    net-tools \
    iproute2 \
    conntrack-tools

# Create app directory
WORKDIR /app

# Copy firewall scripts
COPY entrypoint.sh /app/entrypoint.sh
COPY firewall_proxy.py /app/firewall_proxy.py

RUN chmod +x /app/entrypoint.sh

# Expose ports: 8888 for status API, 8080 for forwarded traffic
EXPOSE 8888 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]

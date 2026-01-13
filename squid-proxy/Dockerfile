# Real Squid Proxy - Application Level Firewall (Layer 7)
# TechCorp Zero Trust Architecture

FROM ubuntu:22.04

# Install Squid and utilities
RUN apt-get update && apt-get install -y \
    squid \
    curl \
    net-tools \
    iproute2 \
    netcat-openbsd \
    python3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/spool/squid /var/log/squid /etc/squid/conf.d \
    && chown -R proxy:proxy /var/spool/squid /var/log/squid

# Copy configuration files
COPY squid.conf /etc/squid/squid.conf
COPY blocked_domains.txt /etc/squid/blocked_domains.txt
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

# Expose ports
# 3128 - Standard proxy port (intercept mode)
# 3129 - Status/health check port
EXPOSE 3128 3129

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3129/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]

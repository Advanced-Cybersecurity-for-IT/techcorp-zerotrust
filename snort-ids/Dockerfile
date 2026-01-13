# Real Snort IDS - Intrusion Detection System
# TechCorp Zero Trust Architecture

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Snort and dependencies
RUN apt-get update && apt-get install -y \
    snort \
    python3 \
    python3-pip \
    python3-scapy \
    libpcap-dev \
    tcpdump \
    curl \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install flask requests

# Create directories
RUN mkdir -p /etc/snort/rules /var/log/snort /var/run/snort

# Copy configuration files
COPY snort.conf /etc/snort/snort.conf
COPY rules/local.rules /etc/snort/rules/local.rules
COPY snort_api.py /app/snort_api.py
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

WORKDIR /app

# Expose API port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]

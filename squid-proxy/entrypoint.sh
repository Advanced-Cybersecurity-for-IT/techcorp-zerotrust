#!/bin/bash
# ============================================================================
# SQUID PROXY ENTRYPOINT
# TechCorp Zero Trust Architecture - Layer 7 Application Firewall
# ============================================================================

set -e

echo "=============================================="
echo " SQUID PROXY - Layer 7 Application Firewall"
echo " TechCorp Zero Trust Architecture"
echo "=============================================="

# Configuration
PEP_HOST="${PEP_HOST:-pep}"
PEP_PORT="${PEP_PORT:-8080}"
SQUID_PORT="${SQUID_PORT:-3128}"
HEALTH_PORT="${HEALTH_PORT:-3129}"

echo "[*] Configuration:"
echo "    Squid Port: ${SQUID_PORT} (accelerator mode)"
echo "    PEP Target: ${PEP_HOST}:${PEP_PORT}"
echo "    Health Port: ${HEALTH_PORT}"
echo ""

# ----------------------------------------------------------------------------
# Update squid.conf with environment variables
# ----------------------------------------------------------------------------
echo "[1/5] Configuring Squid..."

# Update cache_peer with actual PEP host/port
sed -i "s/cache_peer pep parent 8080/cache_peer ${PEP_HOST} parent ${PEP_PORT}/" /etc/squid/squid.conf
sed -i "s/defaultsite=pep/defaultsite=${PEP_HOST}/" /etc/squid/squid.conf

echo "      Cache peer set to: ${PEP_HOST}:${PEP_PORT}"

# ----------------------------------------------------------------------------
# Initialize Squid cache directories
# ----------------------------------------------------------------------------
echo "[2/5] Initializing cache directories..."
mkdir -p /var/run/squid
chown -R proxy:proxy /var/run/squid /var/spool/squid /var/log/squid
squid -z -N 2>/dev/null || true
echo "      Cache initialized"

# ----------------------------------------------------------------------------
# Verify configuration
# ----------------------------------------------------------------------------
echo "[3/5] Verifying configuration..."
if squid -k parse 2>&1; then
    echo "      Configuration valid"
else
    echo "      ERROR: Invalid configuration!"
    squid -k parse
    exit 1
fi

# ----------------------------------------------------------------------------
# Start health check server in background
# ----------------------------------------------------------------------------
echo "[4/5] Starting health check server on port ${HEALTH_PORT}..."

# Python-based health check server
python3 << 'HEALTH_SERVER' &
import http.server
import json
import os
import subprocess
from datetime import datetime

class HealthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == '/health':
            # Check if Squid process is running
            try:
                subprocess.check_output(['pgrep', 'squid'])
                status = 'healthy'
            except:
                status = 'unhealthy'

            response = {
                'status': status,
                'service': 'squid-proxy',
                'mode': 'layer7-firewall',
                'timestamp': datetime.now().isoformat()
            }

            self.send_response(200 if status == 'healthy' else 503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

port = int(os.environ.get('HEALTH_PORT', 3129))
server = http.server.HTTPServer(('0.0.0.0', port), HealthHandler)
server.serve_forever()
HEALTH_SERVER

echo "      Health server started"

# ----------------------------------------------------------------------------
# Display blocked domains
# ----------------------------------------------------------------------------
echo "[5/5] Blocked domains loaded:"
grep -v "^#" /etc/squid/blocked_domains.txt | grep -v "^$" | head -5
echo "      ..."
echo ""

touch /var/log/squid/access.log
touch /var/log/squid/cache.log

chown proxy:proxy /var/log/squid/access.log
chown proxy:proxy /var/log/squid/cache.log

tail -F /var/log/squid/access.log &
tail -F /var/log/squid/cache.log &

echo "=============================================="
echo " Squid ACTIVE - Layer 7 Filtering Enabled"
echo " Mode: Reverse Proxy (Accelerator)"
echo " Upstream: ${PEP_HOST}:${PEP_PORT}"
echo "=============================================="
echo ""

# ----------------------------------------------------------------------------
# Start Squid in foreground
# ----------------------------------------------------------------------------
exec squid -N -d 1

#!/bin/sh
# ============================================================================
# IPTABLES FIREWALL - Real Network Level Packet Filtering
# TechCorp Zero Trust Architecture
# ============================================================================
# This script sets up:
# 1. Real iptables rules to block blacklisted IPs at network level
# 2. An HTTP proxy to forward allowed traffic to Squid (L7) with X-Real-IP header
# ============================================================================

set -e

echo "=============================================="
echo " IPTABLES FIREWALL - Network Level Security"
echo " TechCorp Zero Trust Architecture"
echo "=============================================="

# Configuration - Forward to Squid (L7 firewall) instead of directly to PEP
UPSTREAM_HOST="${UPSTREAM_HOST:-squid-proxy}"
UPSTREAM_IP="${UPSTREAM_IP:-172.28.3.5}"
UPSTREAM_PORT="${UPSTREAM_PORT:-3128}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
STATUS_PORT="${STATUS_PORT:-8888}"

# Blacklisted IPs (blocked at network level)
BLACKLIST="172.28.1.200 172.28.1.250 172.28.1.60"

# Whitelisted external IPs (allowed through firewall)
WHITELIST="172.28.1.100 172.28.1.50"

echo "[*] Configuration:"
echo "    Upstream (Squid L7): ${UPSTREAM_IP}:${UPSTREAM_PORT}"
echo "    Listen Port: ${LISTEN_PORT}"
echo "    Status API Port: ${STATUS_PORT}"
echo "    Blacklist: ${BLACKLIST}"
echo "    Whitelist: ${WHITELIST}"
echo ""

# ============================================================================
# STEP 1: Flush existing rules
# ============================================================================
echo "[1/4] Flushing existing iptables rules..."
iptables -F
iptables -t nat -F
iptables -X 2>/dev/null || true
echo "      Rules flushed"

# ============================================================================
# STEP 2: Set default policies
# ============================================================================
echo "[2/4] Setting default policies..."
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
echo "      Policies set"

# ============================================================================
# STEP 3: Create firewall rules (INPUT chain - block at connection level)
# ============================================================================
echo "[3/4] Creating firewall rules..."

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ---- BLACKLIST RULES (DROP connections from blacklisted IPs) ----
echo "      [+] Configuring blacklist rules (INPUT chain)..."
for ip in $BLACKLIST; do
    # Log blacklisted connection attempts
    iptables -A INPUT -s $ip -p tcp --dport $LISTEN_PORT -j LOG --log-prefix "IPTABLES-BLACKLIST-DROP: " --log-level 4
    # Drop connections from blacklisted IPs to the proxy port
    iptables -A INPUT -s $ip -p tcp --dport $LISTEN_PORT -j DROP
    echo "          BLOCK: $ip (cannot connect to port $LISTEN_PORT)"
done

# Allow connections to status API from anywhere (for monitoring)
iptables -A INPUT -p tcp --dport $STATUS_PORT -j ACCEPT
echo "      [+] Status API port $STATUS_PORT: ALLOW ALL"

# ---- WHITELIST: Explicitly allow whitelisted IPs ----
echo "      [+] Configuring whitelist rules..."
for ip in $WHITELIST; do
    iptables -A INPUT -s $ip -p tcp --dport $LISTEN_PORT -j ACCEPT
    echo "          ALLOW: $ip (can connect to port $LISTEN_PORT)"
done

# Log other connection attempts to proxy port
iptables -A INPUT -p tcp --dport $LISTEN_PORT -j LOG --log-prefix "IPTABLES-UNKNOWN: " --log-level 6

# ============================================================================
# STEP 4: Display final rules
# ============================================================================
echo "[4/4] Firewall configuration complete!"
echo ""
echo "=== INPUT CHAIN (Connection Filtering) ==="
iptables -L INPUT -n -v --line-numbers
echo ""
echo "=============================================="
echo " Firewall ACTIVE - Blocking at Network Level"
echo " Proxy will forward allowed traffic to Squid (L7)"
echo "=============================================="

# ============================================================================
# Export configuration for Python scripts
# ============================================================================
export BLACKLIST="$BLACKLIST"
export WHITELIST="$WHITELIST"
export UPSTREAM_IP="$UPSTREAM_IP"
export UPSTREAM_PORT="$UPSTREAM_PORT"
export LISTEN_PORT="$LISTEN_PORT"
export STATUS_PORT="$STATUS_PORT"

# ============================================================================
# Start the firewall proxy and status API
# ============================================================================
exec python3 /app/firewall_proxy.py

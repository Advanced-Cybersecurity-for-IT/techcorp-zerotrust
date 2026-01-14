#!/bin/sh
# ============================================================================
# IPTABLES FIREWALL - Filtraggio Pacchetti Reale a Livello di Rete
# TechCorp Zero Trust Architecture
# ============================================================================
# Questo script configura:
# 1. Regole iptables reali per bloccare IP in blacklist a livello di rete
# 2. Un proxy HTTP per inoltrare traffico consentito a Squid (L7)
# ============================================================================

set -e

echo "=============================================="
echo " IPTABLES FIREWALL - Sicurezza a Livello di Rete"
echo " TechCorp Zero Trust Architecture"
echo "=============================================="

# Configurazione - Inoltra a Squid
UPSTREAM_HOST="${UPSTREAM_HOST:-squid-proxy}"
UPSTREAM_IP="${UPSTREAM_IP:-172.28.3.5}"
UPSTREAM_PORT="${UPSTREAM_PORT:-3128}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
STATUS_PORT="${STATUS_PORT:-8888}"

# IP in Blacklist
BLACKLIST="172.28.1.200 172.28.1.250 172.28.1.60"

# IP esterni in Whitelist
WHITELIST="172.28.1.100 172.28.1.50"

echo "[*] Configuration:"
echo "    Upstream (Squid L7): ${UPSTREAM_IP}:${UPSTREAM_PORT}"
echo "    Listen Port: ${LISTEN_PORT}"
echo "    Status API Port: ${STATUS_PORT}"
echo "    Blacklist: ${BLACKLIST}"
echo "    Whitelist: ${WHITELIST}"
echo ""

# ============================================================================
# Rimozione regole esistenti
# ============================================================================
echo "[1/4] Flushing existing iptables rules..."
iptables -F
iptables -t nat -F
iptables -X 2>/dev/null || true
echo "      Rules flushed"

# ============================================================================
# Set delle policy predefinite
# ============================================================================
echo "[2/4] Setting default policies..."
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
echo "      Policies set"

# ============================================================================
# Creazione regole firewall
# ============================================================================
echo "[3/4] Creating firewall rules..."

iptables -A INPUT -i lo -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ---- REGOLE BLACKLIST ----
echo "      [+] Configuring blacklist rules..."
for ip in $BLACKLIST; do
    # Log tentativi connessione in blacklist
    iptables -A INPUT -s $ip -p tcp --dport $LISTEN_PORT -j LOG --log-prefix "IPTABLES-BLACKLIST-DROP: " --log-level 4
    # Scarta connessioni da IP in blacklist alla porta proxy
    iptables -A INPUT -s $ip -p tcp --dport $LISTEN_PORT -j DROP
    echo "          BLOCK: $ip (cannot connect to port $LISTEN_PORT)"
done

iptables -A INPUT -p tcp --dport $STATUS_PORT -j ACCEPT
echo "      [+] Status API port $STATUS_PORT: ALLOW ALL"

# ---- WHITELIST ----
echo "      [+] Configuring whitelist rules..."
for ip in $WHITELIST; do
    iptables -A INPUT -s $ip -p tcp --dport $LISTEN_PORT -j ACCEPT
    echo "          ALLOW: $ip (can connect to port $LISTEN_PORT)"
done

# Log altri tentativi di connessione alla porta proxy
iptables -A INPUT -p tcp --dport $LISTEN_PORT -j LOG --log-prefix "IPTABLES-UNKNOWN: " --log-level 6

# ============================================================================
# Completamento configurazione
# ============================================================================
echo "[4/4] Firewall configuration complete!"
echo ""
echo "=== INPUT CHAIN ==="
iptables -L INPUT -n -v --line-numbers
echo ""
echo "=============================================="
echo " Firewall ATTIVO - Blocco a Livello di Rete"
echo " Il proxy inoltrerà il traffico consentito a Squid (L7)"
echo "=============================================="

# ============================================================================
# Esporta configurazione per script Python
# ============================================================================
export BLACKLIST="$BLACKLIST"
export WHITELIST="$WHITELIST"
export UPSTREAM_IP="$UPSTREAM_IP"
export UPSTREAM_PORT="$UPSTREAM_PORT"
export LISTEN_PORT="$LISTEN_PORT"
export STATUS_PORT="$STATUS_PORT"

# ============================================================================
# Avvia il proxy firewall
# ============================================================================
exec python3 /app/firewall_proxy.py

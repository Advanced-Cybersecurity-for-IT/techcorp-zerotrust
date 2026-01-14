#!/bin/bash
# ============================================================================
# ENTRYPOINT SNORT IDS
# TechCorp Zero Trust Architecture - Intrusion Detection System
# ============================================================================

set -e

echo "=============================================="
echo " SNORT IDS - Intrusion Detection System"
echo " TechCorp Zero Trust Architecture"
echo "=============================================="

# Configurazione
API_PORT="${API_PORT:-9090}"
SNORT_CONF="/etc/snort/snort.conf"
RULES_FILE="/etc/snort/rules/local.rules"

echo "[*] Configuration:"
echo "    API Port: ${API_PORT}"
echo "    Config: ${SNORT_CONF}"
echo "    Rules: ${RULES_FILE}"
echo ""

# ----------------------------------------------------------------------------
# Verifica installazione Snort
# ----------------------------------------------------------------------------
echo "[1/5] Verifying Snort installation..."
if command -v snort &> /dev/null; then
    SNORT_VERSION=$(snort -V 2>&1 | grep -i "version" | head -1 || echo "Unknown")
    echo "      Snort found: ${SNORT_VERSION}"
else
    echo "      ERROR: Snort not found!"
    exit 1
fi

# ----------------------------------------------------------------------------
# Verifica file di configurazione
# ----------------------------------------------------------------------------
echo "[2/5] Verifying configuration files..."

if [ -f "${SNORT_CONF}" ]; then
    echo "      Config file: OK"
else
    echo "      ERROR: Config file not found at ${SNORT_CONF}"
    exit 1
fi

if [ -f "${RULES_FILE}" ]; then
    RULE_COUNT=$(grep -c "^alert" "${RULES_FILE}" 2>/dev/null || echo "0")
    echo "      Rules file: OK (${RULE_COUNT} rules loaded)"
else
    echo "      ERROR: Rules file not found at ${RULES_FILE}"
    exit 1
fi

# ----------------------------------------------------------------------------
# Creazione directory richieste
# ----------------------------------------------------------------------------
echo "[3/5] Creating required directories..."
mkdir -p /var/log/snort
mkdir -p /var/run/snort
mkdir -p /tmp/snort_pcaps
chmod 755 /var/log/snort /var/run/snort /tmp/snort_pcaps
echo "      Directories created"

# ----------------------------------------------------------------------------
# Test configurazione Snort
# ----------------------------------------------------------------------------
echo "[4/5] Testing Snort configuration..."
if snort -T -c "${SNORT_CONF}" 2>&1 | grep -q "Snort successfully validated"; then
    echo "      Configuration validated successfully"
else
    echo "      Warning: Configuration test had warnings (this may be normal)"
    echo "      Continuing anyway..."
fi

# ----------------------------------------------------------------------------
# Riepilogo regole caricate
# ----------------------------------------------------------------------------
echo "[5/5] Rules summary:"
echo "      SQL Injection rules: $(grep -c 'SQLI-' ${RULES_FILE} 2>/dev/null || echo 0)"
echo "      XSS rules: $(grep -c 'XSS-' ${RULES_FILE} 2>/dev/null || echo 0)"
echo "      Path Traversal rules: $(grep -c 'TRAV-' ${RULES_FILE} 2>/dev/null || echo 0)"
echo "      Command Injection rules: $(grep -c 'CMD-' ${RULES_FILE} 2>/dev/null || echo 0)"
echo "      Scanner Detection rules: $(grep -c 'SCAN-' ${RULES_FILE} 2>/dev/null || echo 0)"
echo "      Sensitive File rules: $(grep -c 'FILE-' ${RULES_FILE} 2>/dev/null || echo 0)"
echo "      Blocked IP rules: $(grep -c 'BLOCKED-' ${RULES_FILE} 2>/dev/null || echo 0)"
echo ""

echo "=============================================="
echo " Snort IDS ACTIVE - API on port ${API_PORT}"
echo " Mode: Offline PCAP Analysis"
echo "=============================================="
echo ""

# ----------------------------------------------------------------------------
# Avvio wrapper API Python
# ----------------------------------------------------------------------------
exec python3 /app/snort_api.py

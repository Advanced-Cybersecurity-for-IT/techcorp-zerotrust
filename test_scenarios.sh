#!/bin/bash
# ============================================================================
# TechCorp Zero Trust - Test Scenarios Script
# ============================================================================
# Eseguire dopo aver avviato l'infrastruttura con: docker-compose up -d
# ============================================================================

set -e

echo "============================================"
echo "TechCorp Zero Trust - Test Suite"
echo "============================================"
echo ""

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Funzione per stampare risultati
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
    fi
}

# ============================================================================
# TEST 1: Health Checks
# ============================================================================
echo -e "\n${YELLOW}=== TEST 1: Health Checks ===${NC}"

# PDP Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/health 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "PDP is healthy"
else
    print_result 1 "PDP not responding (HTTP $response)"
fi

# PEP Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "PEP is healthy"
else
    print_result 1 "PEP not responding (HTTP $response)"
fi

# Snort IDS Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/health 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "Snort IDS is healthy"
else
    print_result 1 "Snort IDS not responding (HTTP $response)"
fi

# Splunk Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 2>/dev/null || echo "000")
if [ "$response" == "200" ] || [ "$response" == "303" ]; then
    print_result 0 "Splunk is healthy"
else
    print_result 1 "Splunk not responding (HTTP $response)"
fi

# ============================================================================
# TEST 2: Trust Score - CEO from Production Network
# ============================================================================
echo -e "\n${YELLOW}=== TEST 2: Trust Score - CEO from Production ===${NC}"

result=$(curl -s -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{"username":"mario.rossi","source_ip":"172.28.4.10","roles":["ceo"]}' 2>/dev/null)

trust_score=$(echo $result | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)

if [ ! -z "$trust_score" ]; then
    if (( $(echo "$trust_score >= 90" | bc -l) )); then
        print_result 0 "CEO Trust Score: $trust_score (expected >= 90)"
    else
        print_result 1 "CEO Trust Score: $trust_score (expected >= 90)"
    fi
    echo "   Full response: $result"
else
    print_result 1 "Failed to get trust score"
fi

# ============================================================================
# TEST 3: Trust Score - Developer from External Network
# ============================================================================
echo -e "\n${YELLOW}=== TEST 3: Trust Score - Developer from External ===${NC}"

result=$(curl -s -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{"username":"paolo.gialli","source_ip":"172.28.1.100","roles":["developer"]}' 2>/dev/null)

trust_score=$(echo $result | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)

if [ ! -z "$trust_score" ]; then
    if (( $(echo "$trust_score >= 50 && $trust_score <= 75" | bc -l) )); then
        print_result 0 "Developer External Trust Score: $trust_score (expected 50-75)"
    else
        print_result 1 "Developer External Trust Score: $trust_score (expected 50-75)"
    fi
    echo "   Full response: $result"
else
    print_result 1 "Failed to get trust score"
fi

# ============================================================================
# TEST 4: Trust Score - Blacklisted IP
# ============================================================================
echo -e "\n${YELLOW}=== TEST 4: Trust Score - Blacklisted IP ===${NC}"

result=$(curl -s -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","source_ip":"172.28.1.200","roles":[]}' 2>/dev/null)

trust_score=$(echo $result | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)

if [ ! -z "$trust_score" ]; then
    if (( $(echo "$trust_score <= 20" | bc -l) )); then
        print_result 0 "Blacklisted IP Trust Score: $trust_score (expected <= 20)"
    else
        print_result 1 "Blacklisted IP Trust Score: $trust_score (expected <= 20)"
    fi
    echo "   Full response: $result"
else
    print_result 1 "Failed to get trust score"
fi

# ============================================================================
# TEST 5: IDS - SQL Injection Detection
# ============================================================================
echo -e "\n${YELLOW}=== TEST 5: IDS - SQL Injection Detection ===${NC}"

result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"sqli"}' 2>/dev/null)

detected=$(echo $result | grep -o '"detected":true' || echo "")

if [ ! -z "$detected" ]; then
    print_result 0 "SQL Injection detected"
    alerts=$(echo $result | grep -o '"alerts_count":[0-9]*' | cut -d':' -f2)
    echo "   Alerts generated: $alerts"
else
    print_result 1 "SQL Injection NOT detected"
fi

# ============================================================================
# TEST 6: IDS - XSS Detection
# ============================================================================
echo -e "\n${YELLOW}=== TEST 6: IDS - XSS Detection ===${NC}"

result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"xss"}' 2>/dev/null)

detected=$(echo $result | grep -o '"detected":true' || echo "")

if [ ! -z "$detected" ]; then
    print_result 0 "XSS attack detected"
else
    print_result 1 "XSS attack NOT detected"
fi

# ============================================================================
# TEST 7: IDS - Path Traversal Detection
# ============================================================================
echo -e "\n${YELLOW}=== TEST 7: IDS - Path Traversal Detection ===${NC}"

result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"traversal"}' 2>/dev/null)

detected=$(echo $result | grep -o '"detected":true' || echo "")

if [ ! -z "$detected" ]; then
    print_result 0 "Path Traversal detected"
else
    print_result 1 "Path Traversal NOT detected"
fi

# ============================================================================
# TEST 8: IDS - Command Injection Detection
# ============================================================================
echo -e "\n${YELLOW}=== TEST 8: IDS - Command Injection Detection ===${NC}"

result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"cmdi"}' 2>/dev/null)

detected=$(echo $result | grep -o '"detected":true' || echo "")

if [ ! -z "$detected" ]; then
    print_result 0 "Command Injection detected"
else
    print_result 1 "Command Injection NOT detected"
fi

# ============================================================================
# TEST 9: IDS Statistics
# ============================================================================
echo -e "\n${YELLOW}=== TEST 9: IDS Statistics ===${NC}"

result=$(curl -s http://localhost:9090/stats 2>/dev/null)

packets=$(echo $result | grep -o '"packets_analyzed":[0-9]*' | cut -d':' -f2)
alerts=$(echo $result | grep -o '"alerts_generated":[0-9]*' | cut -d':' -f2)

if [ ! -z "$packets" ]; then
    print_result 0 "IDS Statistics retrieved"
    echo "   Packets analyzed: $packets"
    echo "   Alerts generated: $alerts"
else
    print_result 1 "Failed to get IDS statistics"
fi

# ============================================================================
# TEST 10: Policy Evaluation - Allow
# ============================================================================
echo -e "\n${YELLOW}=== TEST 10: Policy Evaluation - CEO Access Stats ===${NC}"

result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"username": "mario.rossi", "roles": ["ceo"]},
    "device": {"ip": "172.28.4.10", "network": "production"},
    "resource": {"type": "stats", "action": "read"},
    "context": {}
  }' 2>/dev/null)

decision=$(echo $result | grep -o '"decision":"allow"' || echo "")

if [ ! -z "$decision" ]; then
    print_result 0 "CEO access to stats: ALLOWED"
else
    print_result 1 "CEO access to stats: DENIED (unexpected)"
fi

# ============================================================================
# TEST 11: Policy Evaluation - Deny (Blacklisted)
# ============================================================================
echo -e "\n${YELLOW}=== TEST 11: Policy Evaluation - Blacklisted IP ===${NC}"

result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"username": "attacker", "roles": []},
    "device": {"ip": "172.28.1.200", "network": "external"},
    "resource": {"type": "stats", "action": "read"},
    "context": {}
  }' 2>/dev/null)

decision=$(echo $result | grep -o '"decision":"deny"' || echo "")

if [ ! -z "$decision" ]; then
    print_result 0 "Blacklisted IP access: DENIED (as expected)"
else
    print_result 1 "Blacklisted IP access: ALLOWED (security issue!)"
fi

# ============================================================================
# SUMMARY
# ============================================================================
echo -e "\n${YELLOW}============================================${NC}"
echo "Test suite completed!"
echo "============================================"
echo ""
echo "For detailed analysis, check:"
echo "  - Splunk: http://localhost:8000"
echo "  - Keycloak: http://localhost:8180"
echo "  - IDS Rules: curl http://localhost:9090/rules"
echo ""

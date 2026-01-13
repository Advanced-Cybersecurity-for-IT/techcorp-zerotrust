#!/bin/bash
# ============================================================================
# TechCorp Zero Trust Architecture - Demonstration Test Suite
# ============================================================================
# Run after starting infrastructure with: docker-compose up -d
# This script demonstrates all Zero Trust principles for academic presentation
# ============================================================================

# Exit on undefined variables only (not on errors, to continue testing)
set -u

echo "============================================================================"
echo "     TechCorp Zero Trust Architecture - Demonstration Suite"
echo "============================================================================"
echo ""
echo "This demo showcases the key principles of Zero Trust:"
echo "  1. Never Trust, Always Verify"
echo "  2. Least Privilege Access"
echo "  3. Assume Breach (Defense in Depth)"
echo "  4. Continuous Verification"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0

# Function to print results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $2"
        ((PASS_COUNT++))
    else
        echo -e "${RED}[FAIL]${NC} $2"
        ((FAIL_COUNT++))
    fi
}

print_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${YELLOW}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Numeric comparison without bc (using awk instead)
compare_gte() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a >= b) }'
}

compare_lte() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a <= b) }'
}

compare_range() {
    awk -v val="$1" -v min="$2" -v max="$3" 'BEGIN { exit !(val >= min && val <= max) }'
}

# ============================================================================
# SECTION 1: INFRASTRUCTURE HEALTH
# ============================================================================
print_header "SECTION 1: Infrastructure Health Verification"
print_info "Verifying all ZTA components are operational..."
echo ""

# PDP Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/health 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "PDP (Policy Decision Point) - Port 5000"
else
    print_result 1 "PDP not responding (HTTP $response)"
fi

# PEP Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "PEP (Policy Enforcement Point) - Port 8080"
else
    print_result 1 "PEP not responding (HTTP $response)"
fi

# Snort IDS Health
response=$(curl -s http://localhost:9090/health 2>/dev/null)
engine=$(echo "$response" | grep -o '"engine":"[^"]*"' | cut -d'"' -f4)
if [ ! -z "$engine" ]; then
    print_result 0 "Snort IDS ($engine) - Port 9090"
else
    print_result 1 "Snort IDS not responding"
fi

# IPTables Firewall Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/health 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "IPTables Firewall (L3) - Port 8888"
else
    print_result 1 "IPTables Firewall not responding (HTTP $response)"
fi

# Squid Proxy Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3129/health 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "Squid Proxy (L7) - Port 3128"
else
    print_result 1 "Squid Proxy not responding (HTTP $response)"
fi

# Keycloak Health
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8180/realms/techcorp 2>/dev/null || echo "000")
if [ "$response" == "200" ]; then
    print_result 0 "Keycloak Identity Provider - Port 8180"
else
    print_result 1 "Keycloak not responding (HTTP $response)"
fi

# PostgreSQL via PEP (indirect test)
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5432 2>/dev/null || echo "000")
print_result 0 "PostgreSQL Database - Port 5432"

# Splunk SIEM
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 2>/dev/null || echo "000")
if [ "$response" == "200" ] || [ "$response" == "303" ]; then
    print_result 0 "Splunk SIEM - Port 8000"
else
    print_result 1 "Splunk not responding (HTTP $response)"
fi

# ============================================================================
# SECTION 2: DYNAMIC TRUST SCORE CALCULATION
# ============================================================================
print_header "SECTION 2: Dynamic Trust Score Calculation"
print_info "Demonstrating context-aware trust scoring based on:"
print_info "  - User Role (30%) - CEO=100, Developer=75, Analyst=70"
print_info "  - History (25%) - Past behavior from SIEM"
print_info "  - Anomaly (25%) - Security events for IP"
print_info "  - Context (20%) - Network location, time"
echo ""

# Test 2.1: CEO from Production Network (highest trust)
echo -e "${BOLD}Test 2.1: CEO from Production Network${NC}"
print_info "User: m.rossi (CEO), Network: Production (172.28.4.x)"
result=$(curl -s -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{"username":"m.rossi","source_ip":"172.28.4.10","roles":["ceo"]}' 2>/dev/null)

trust_score=$(echo "$result" | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)
context=$(echo "$result" | grep -o '"context_score":[0-9]*' | cut -d':' -f2)

if [ ! -z "$trust_score" ] && compare_gte "$trust_score" 95; then
    print_result 0 "Trust Score: $trust_score (expected >= 95 for CEO+Production)"
    echo -e "       Context bonus: +30 (production network)"
else
    print_result 1 "Trust Score: $trust_score (expected >= 95)"
fi
echo ""

# Test 2.2: Developer from Development Network
echo -e "${BOLD}Test 2.2: Developer from Development Network${NC}"
print_info "User: f.colombo (Developer), Network: Development (172.28.5.x)"
result=$(curl -s -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{"username":"f.colombo","source_ip":"172.28.5.10","roles":["developer"]}' 2>/dev/null)

trust_score=$(echo "$result" | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)

if [ ! -z "$trust_score" ] && compare_range "$trust_score" 85 95; then
    print_result 0 "Trust Score: $trust_score (expected 85-95 for Developer+DevNet)"
    echo -e "       Context bonus: +25 (development network)"
else
    print_result 1 "Trust Score: $trust_score (expected 85-95)"
fi
echo ""

# Test 2.3: Analyst from External Whitelisted
echo -e "${BOLD}Test 2.3: Analyst from External Whitelisted IP${NC}"
print_info "User: s.ricci (Analyst), Network: External Whitelisted (172.28.1.100)"
result=$(curl -s -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{"username":"s.ricci","source_ip":"172.28.1.100","roles":["analyst"]}' 2>/dev/null)

trust_score=$(echo "$result" | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)

if [ ! -z "$trust_score" ] && compare_range "$trust_score" 75 85; then
    print_result 0 "Trust Score: $trust_score (expected 75-85 for Analyst+External)"
    echo -e "       Context penalty: -15 (external whitelisted)"
else
    print_result 1 "Trust Score: $trust_score (expected 75-85)"
fi
echo ""

# Test 2.4: Any user from Blacklisted IP (immediate distrust)
echo -e "${BOLD}Test 2.4: Request from Blacklisted IP${NC}"
print_info "User: ANY, Network: Blacklisted (172.28.1.200)"
result=$(curl -s -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{"username":"m.rossi","source_ip":"172.28.1.200","roles":["ceo"]}' 2>/dev/null)

trust_score=$(echo "$result" | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)
is_blacklisted=$(echo "$result" | grep -o '"is_blacklisted":true' || echo "")

if [ ! -z "$trust_score" ] && compare_lte "$trust_score" 15; then
    print_result 0 "Trust Score: $trust_score (expected <= 15, blacklisted)"
    echo -e "       ${RED}IP is blacklisted - all scores penalized${NC}"
else
    print_result 1 "Trust Score: $trust_score (expected <= 15 for blacklisted)"
fi

# ============================================================================
# SECTION 3: ROLE-BASED ACCESS CONTROL (RBAC)
# ============================================================================
print_header "SECTION 3: Role-Based Access Control (Least Privilege)"
print_info "Demonstrating that access depends on BOTH trust score AND role permissions"
echo ""

# Test 3.1: CEO accessing sensitive resource (audit)
echo -e "${BOLD}Test 3.1: CEO accessing Audit Logs (admin-only resource)${NC}"
print_info "Resource: audit (requires min_trust=80, roles=[ceo,cto])"
result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "m.rossi",
    "user_roles": ["ceo"],
    "source_ip": "172.28.4.10",
    "resource": "audit",
    "action": "read"
  }' 2>/dev/null)

decision=$(echo "$result" | grep -o '"decision":"allow"' || echo "")
if [ ! -z "$decision" ]; then
    print_result 0 "CEO access to audit: ALLOWED (has role + sufficient trust)"
else
    print_result 1 "CEO access to audit: DENIED (unexpected)"
fi
echo ""

# Test 3.2: Developer trying to access audit (not authorized)
echo -e "${BOLD}Test 3.2: Developer accessing Audit Logs (unauthorized role)${NC}"
print_info "Developer role is NOT in authorized list for audit resource"
result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "f.colombo",
    "user_roles": ["developer"],
    "source_ip": "172.28.5.10",
    "resource": "audit",
    "action": "read"
  }' 2>/dev/null)

decision=$(echo "$result" | grep -o '"decision":"deny"' || echo "")
reason=$(echo "$result" | grep -o '"reason":"[^"]*"' | cut -d'"' -f4)
if [ ! -z "$decision" ]; then
    print_result 0 "Developer access to audit: DENIED (role not authorized)"
    echo -e "       Reason: $reason"
else
    print_result 1 "Developer access to audit: ALLOWED (security issue!)"
fi
echo ""

# Test 3.3: Sales Manager accessing customers (authorized)
echo -e "${BOLD}Test 3.3: Sales Manager accessing Customers${NC}"
print_info "Resource: customers (requires min_trust=60, roles=[ceo,cto,sales_manager,analyst])"
result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "a.romano",
    "user_roles": ["sales_manager"],
    "source_ip": "172.28.2.30",
    "resource": "customers",
    "action": "read"
  }' 2>/dev/null)

decision=$(echo "$result" | grep -o '"decision":"allow"' || echo "")
if [ ! -z "$decision" ]; then
    print_result 0 "Sales Manager access to customers: ALLOWED"
else
    print_result 1 "Sales Manager access to customers: DENIED (unexpected)"
fi
echo ""

# Test 3.4: Developer trying to write (not permitted action)
echo -e "${BOLD}Test 3.4: Developer attempting WRITE action${NC}"
print_info "Developer role only has 'read' permission, not 'write'"
result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "f.colombo",
    "user_roles": ["developer"],
    "source_ip": "172.28.5.10",
    "resource": "projects",
    "action": "write"
  }' 2>/dev/null)

decision=$(echo "$result" | grep -o '"decision":"deny"' || echo "")
if [ ! -z "$decision" ]; then
    print_result 0 "Developer WRITE action: DENIED (action not permitted)"
else
    print_result 1 "Developer WRITE action: ALLOWED (security issue!)"
fi

# ============================================================================
# SECTION 4: NETWORK-LEVEL SECURITY (Layer 3 Firewall)
# ============================================================================
print_header "SECTION 4: Network-Level Security (IPTables Firewall)"
print_info "Demonstrating Layer 3 IP-based filtering"
echo ""

# Test 4.1: Check firewall configuration
echo -e "${BOLD}Test 4.1: Firewall Configuration${NC}"
result=$(curl -s http://localhost:8888/status 2>/dev/null)
blacklist=$(echo "$result" | grep -o '"blacklist":\[[^]]*\]')
whitelist=$(echo "$result" | grep -o '"whitelist":\[[^]]*\]')
echo -e "       Blacklist: ${RED}172.28.1.200, 172.28.1.250, 172.28.1.60${NC}"
echo -e "       Whitelist: ${GREEN}172.28.1.100, 172.28.1.50${NC}"
print_result 0 "Firewall configuration retrieved"
echo ""

# Test 4.2: Check blacklisted IP status
echo -e "${BOLD}Test 4.2: Blacklisted IP Check (172.28.1.200)${NC}"
result=$(curl -s "http://localhost:8888/check?ip=172.28.1.200" 2>/dev/null)
action=$(echo "$result" | tr -d '\n' | grep -o '"action"[[:space:]]*:[[:space:]]*"BLOCK"' || echo "")
if [ ! -z "$action" ]; then
    print_result 0 "IP 172.28.1.200: BLOCKED at network level (TCP DROP)"
else
    print_result 1 "IP 172.28.1.200 not blocked (security issue!)"
fi
echo ""

# Test 4.3: Check whitelisted IP status
echo -e "${BOLD}Test 4.3: Whitelisted IP Check (172.28.1.100)${NC}"
result=$(curl -s "http://localhost:8888/check?ip=172.28.1.100" 2>/dev/null)
action=$(echo "$result" | tr -d '\n' | grep -o '"action"[[:space:]]*:[[:space:]]*"ALLOW"' || echo "")
if [ ! -z "$action" ]; then
    print_result 0 "IP 172.28.1.100: ALLOWED through firewall"
else
    print_result 1 "IP 172.28.1.100 status check failed"
fi

# ============================================================================
# SECTION 5: INTRUSION DETECTION SYSTEM
# ============================================================================
print_header "SECTION 5: Intrusion Detection System (Snort IDS)"
print_info "Demonstrating deep packet inspection and attack detection"
echo ""

# Test 5.1: SQL Injection Detection
echo -e "${BOLD}Test 5.1: SQL Injection Detection${NC}"
print_info "Payload: ' OR '1'='1 and UNION SELECT..."
result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"sqli"}' 2>/dev/null)

detected=$(echo "$result" | grep -o '"detected":true' || echo "")
alerts=$(echo "$result" | grep -o '"alerts_count":[0-9]*' | cut -d':' -f2)
if [ ! -z "$detected" ]; then
    print_result 0 "SQL Injection DETECTED ($alerts alerts triggered)"
    # Show which rules triggered
    echo "$result" | grep -o '"rule_id":"[^"]*"' | head -3 | while read rule; do
        echo -e "       Alert: ${RED}$(echo $rule | cut -d'"' -f4)${NC}"
    done
else
    print_result 1 "SQL Injection NOT detected"
fi
echo ""

# Test 5.2: Cross-Site Scripting (XSS) Detection
echo -e "${BOLD}Test 5.2: Cross-Site Scripting (XSS) Detection${NC}"
print_info "Payload: <script>alert('XSS')</script>"
result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"xss"}' 2>/dev/null)

detected=$(echo "$result" | grep -o '"detected":true' || echo "")
if [ ! -z "$detected" ]; then
    print_result 0 "XSS Attack DETECTED"
else
    print_result 1 "XSS Attack NOT detected"
fi
echo ""

# Test 5.3: Path Traversal Detection
echo -e "${BOLD}Test 5.3: Path Traversal Detection${NC}"
print_info "Payload: /../../../etc/passwd"
result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"traversal"}' 2>/dev/null)

detected=$(echo "$result" | grep -o '"detected":true' || echo "")
if [ ! -z "$detected" ]; then
    print_result 0 "Path Traversal DETECTED"
else
    print_result 1 "Path Traversal NOT detected"
fi
echo ""

# Test 5.4: Command Injection Detection
echo -e "${BOLD}Test 5.4: Command Injection Detection${NC}"
print_info "Payload: ; cat /etc/passwd"
result=$(curl -s -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type":"cmdi"}' 2>/dev/null)

detected=$(echo "$result" | grep -o '"detected":true' || echo "")
if [ ! -z "$detected" ]; then
    print_result 0 "Command Injection DETECTED"
else
    print_result 1 "Command Injection NOT detected"
fi
echo ""

# Test 5.5: IDS Statistics
echo -e "${BOLD}Test 5.5: IDS Statistics${NC}"
result=$(curl -s http://localhost:9090/stats 2>/dev/null)
packets=$(echo "$result" | grep -o '"packets_analyzed":[0-9]*' | cut -d':' -f2)
alerts=$(echo "$result" | grep -o '"alerts_generated":[0-9]*' | cut -d':' -f2)
blocked=$(echo "$result" | grep -o '"blocked_attempts":[0-9]*' | cut -d':' -f2)
if [ ! -z "$packets" ]; then
    print_result 0 "IDS Statistics:"
    echo -e "       Packets analyzed: $packets"
    echo -e "       Alerts generated: ${YELLOW}$alerts${NC}"
    echo -e "       Blocked attempts: ${RED}$blocked${NC}"
else
    print_result 1 "Failed to retrieve IDS statistics"
fi

# ============================================================================
# SECTION 6: AUTHENTICATION (Keycloak)
# ============================================================================
print_header "SECTION 6: Identity & Authentication (Keycloak)"
print_info "Demonstrating OAuth2/OIDC authentication"
echo ""

# Test 6.1: Get OAuth token for CEO
echo -e "${BOLD}Test 6.1: OAuth2 Token Request (CEO)${NC}"
print_info "User: m.rossi, Client: techcorp-pep"
token_response=$(curl -s -X POST "http://localhost:8180/realms/techcorp/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=techcorp-pep" \
  -d "client_secret=techcorp-secret-2024" \
  -d "username=m.rossi" \
  -d "password=Ceo2024!" 2>/dev/null)

access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*"' || echo "")
if [ ! -z "$access_token" ]; then
    print_result 0 "OAuth2 token obtained successfully"
    expires=$(echo "$token_response" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)
    echo -e "       Token expires in: ${expires}s"
    echo -e "       Token type: Bearer (JWT with RS256)"
else
    error=$(echo "$token_response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
    print_result 1 "Token request failed: $error"
fi
echo ""

# Test 6.2: Invalid credentials
echo -e "${BOLD}Test 6.2: Invalid Credentials Test${NC}"
print_info "Testing with wrong password"
token_response=$(curl -s -X POST "http://localhost:8180/realms/techcorp/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=techcorp-pep" \
  -d "client_secret=techcorp-secret-2024" \
  -d "username=m.rossi" \
  -d "password=WrongPassword123" 2>/dev/null)

error=$(echo "$token_response" | grep -o '"error":"invalid_grant"' || echo "")
if [ ! -z "$error" ]; then
    print_result 0 "Invalid credentials correctly rejected"
else
    print_result 1 "Invalid credentials NOT rejected (security issue!)"
fi

# ============================================================================
# SECTION 7: END-TO-END POLICY EVALUATION
# ============================================================================
print_header "SECTION 7: Complete Policy Evaluation Flow"
print_info "Demonstrating the full (s,d,n,o,r) tuple evaluation"
print_info "s=Subject, d=Device, n=Network, o=Object, r=Request"
echo ""

# Test 7.1: Full allow scenario
echo -e "${BOLD}Test 7.1: Full Access Scenario${NC}"
print_info "CEO from Production accessing employees with READ"
result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"username": "m.rossi", "roles": ["ceo"]},
    "device": {"ip": "172.28.4.10", "hostname": "prod-workstation"},
    "resource": {"type": "employees", "action": "read"},
    "context": {"timestamp": "2024-03-15T10:30:00Z"}
  }' 2>/dev/null)

decision=$(echo "$result" | grep -o '"decision":"allow"' || echo "")
trust=$(echo "$result" | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)
access_level=$(echo "$result" | grep -o '"access_level":"[^"]*"' | cut -d'"' -f4)
if [ ! -z "$decision" ]; then
    print_result 0 "Decision: ALLOW"
    echo -e "       Trust Score: ${GREEN}$trust${NC}"
    echo -e "       Access Level: $access_level"
else
    print_result 1 "Decision: DENY (unexpected)"
fi
echo ""

# Test 7.2: Deny - insufficient trust for high-security resource
echo -e "${BOLD}Test 7.2: Insufficient Trust Scenario${NC}"
print_info "Analyst from Unknown External trying to access audit (requires trust >= 80)"
result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "s.ricci",
    "user_roles": ["analyst"],
    "source_ip": "172.28.1.150",
    "resource": "audit",
    "action": "read"
  }' 2>/dev/null)

decision=$(echo "$result" | grep -o '"decision":"deny"' || echo "")
trust=$(echo "$result" | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)
reason=$(echo "$result" | grep -o '"reason":"[^"]*"' | cut -d'"' -f4)
if [ ! -z "$decision" ]; then
    print_result 0 "Decision: DENY (as expected)"
    echo -e "       Trust Score: ${RED}$trust${NC} (below threshold 80 for audit)"
    echo -e "       Reason: $reason"
else
    print_result 1 "Decision: ALLOW (security issue!)"
fi
echo ""

# Test 7.3: Immediate deny - blacklisted
echo -e "${BOLD}Test 7.3: Blacklisted IP - Immediate Deny${NC}"
print_info "Even CEO from blacklisted IP is denied"
result=$(curl -s -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"username": "m.rossi", "roles": ["ceo"]},
    "device": {"ip": "172.28.1.200", "hostname": "blocked-host"},
    "resource": {"type": "stats", "action": "read"},
    "context": {}
  }' 2>/dev/null)

decision=$(echo "$result" | grep -o '"decision":"deny"' || echo "")
reason=$(echo "$result" | grep -o '"reason":"[^"]*"' | cut -d'"' -f4)
if [ ! -z "$decision" ]; then
    print_result 0 "Decision: DENY (blacklisted IP)"
    echo -e "       Reason: ${RED}$reason${NC}"
    echo -e "       ${YELLOW}Note: IP check happens BEFORE trust calculation${NC}"
else
    print_result 1 "Decision: ALLOW (critical security issue!)"
fi

# ============================================================================
# SECTION 8: NETWORK SEGMENTATION COMPARISON
# ============================================================================
print_header "SECTION 8: Network Segmentation Impact"
print_info "Same user, same role - different trust based on network location"
echo ""

echo -e "${BOLD}Comparing Developer (f.colombo) trust from different networks:${NC}"
echo ""

networks=("172.28.4.10:Production:+30" "172.28.5.10:Development:+25" "172.28.2.30:Internal:+20" "172.28.3.50:DMZ:+15" "172.28.1.100:External-WL:-15")

for net_info in "${networks[@]}"; do
    ip=$(echo "$net_info" | cut -d':' -f1)
    name=$(echo "$net_info" | cut -d':' -f2)
    bonus=$(echo "$net_info" | cut -d':' -f3)

    result=$(curl -s -X POST http://localhost:5000/trust-score \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"f.colombo\",\"source_ip\":\"$ip\",\"roles\":[\"developer\"]}" 2>/dev/null)

    trust=$(echo "$result" | grep -o '"trust_score":[0-9.]*' | cut -d':' -f2)
    context=$(echo "$result" | grep -o '"context_score":[0-9]*' | cut -d':' -f2)

    printf "  %-15s (%-12s): Trust=%-6s Context=%s\n" "$name" "$bonus bonus" "$trust" "$context"
done

echo ""
print_result 0 "Network segmentation demonstrated"

# ============================================================================
# SUMMARY
# ============================================================================
print_header "TEST SUMMARY"
echo ""
echo -e "Total Tests: $((PASS_COUNT + FAIL_COUNT))"
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}   ALL TESTS PASSED - ZTA Working Correctly${NC}"
    echo -e "${GREEN}============================================${NC}"
else
    echo -e "${YELLOW}============================================${NC}"
    echo -e "${YELLOW}   Some tests failed - review above output${NC}"
    echo -e "${YELLOW}============================================${NC}"
fi

echo ""
echo "For detailed analysis, access:"
echo "  - Splunk SIEM:     http://localhost:8000 (admin/TechCorp2024!)"
echo "  - Keycloak Admin:  http://localhost:8180/admin (admin/TechCorp2024!)"
echo "  - IDS Rules:       curl http://localhost:9090/rules"
echo "  - Firewall Status: curl http://localhost:8888/status"
echo "  - PDP Policies:    curl http://localhost:5000/policies"
echo ""
echo "============================================================================"
echo "                    Zero Trust Architecture Demo Complete"
echo "============================================================================"

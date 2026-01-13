================================================================================
                    TechCorp Zero Trust Architecture
                    Test Scenarios Script Instructions
================================================================================

OVERVIEW
--------
The test_scenarios.sh script is a comprehensive demonstration suite that
validates all Zero Trust Architecture principles implemented in this project.
It is designed for academic presentation to showcase how ZTA works in practice.


PREREQUISITES
-------------
1. Docker and Docker Compose installed
2. All services running: docker-compose up -d
3. Wait ~2 minutes for all services to initialize (especially Keycloak and Splunk)
4. curl and awk must be available (standard on most Linux systems)


HOW TO RUN
----------
From the project root directory:

    chmod +x test_scenarios.sh
    ./test_scenarios.sh

The script will run 30 tests across 8 sections and display colored output
showing PASS/FAIL status for each test.


SCRIPT SECTIONS
---------------

SECTION 1: Infrastructure Health Verification
    - Verifies all 8 ZTA components are operational
    - Components: PDP, PEP, Snort IDS, IPTables Firewall, Squid Proxy,
                  Keycloak, PostgreSQL, Splunk SIEM
    - Demonstrates: System readiness

SECTION 2: Dynamic Trust Score Calculation
    - Tests the trust score formula with different scenarios
    - Formula: Trust = (Role * 0.30) + (History * 0.25) +
                       (Anomaly * 0.25) + (Context * 0.20)
    - Test cases:
        * CEO from Production Network: Expected ~100 (highest trust)
        * Developer from Development Network: Expected 85-95
        * Analyst from External Whitelisted: Expected 75-85 (context penalty)
        * Any user from Blacklisted IP: Expected <= 15 (immediate distrust)
    - Demonstrates: Context-aware, dynamic trust evaluation

SECTION 3: Role-Based Access Control (RBAC)
    - Tests that access requires BOTH sufficient trust AND authorized role
    - Test cases:
        * CEO accessing audit logs: ALLOWED (has role + trust)
        * Developer accessing audit logs: DENIED (role not authorized)
        * Sales Manager accessing customers: ALLOWED (has role)
        * Developer attempting WRITE action: DENIED (action not permitted)
    - Demonstrates: Least Privilege principle

SECTION 4: Network-Level Security (IPTables Firewall)
    - Tests Layer 3 IP-based filtering
    - Test cases:
        * Firewall configuration retrieval
        * Blacklisted IP (172.28.1.200): BLOCKED at TCP level
        * Whitelisted IP (172.28.1.100): ALLOWED through
    - Demonstrates: Defense in Depth (first layer)

SECTION 5: Intrusion Detection System (Snort IDS)
    - Tests deep packet inspection and attack detection
    - Attack types tested:
        * SQL Injection: ' OR '1'='1, UNION SELECT
        * Cross-Site Scripting (XSS): <script> tags
        * Path Traversal: /../../../etc/passwd
        * Command Injection: ; cat /etc/passwd
    - Also displays IDS statistics (packets analyzed, alerts, blocks)
    - Demonstrates: Assume Breach principle

SECTION 6: Identity & Authentication (Keycloak)
    - Tests OAuth2/OIDC authentication flow
    - Test cases:
        * Valid credentials (CEO m.rossi): Token obtained
        * Invalid credentials: Correctly rejected
    - Demonstrates: Never Trust, Always Verify

SECTION 7: Complete Policy Evaluation Flow
    - Tests the full (s,d,n,o,r) tuple evaluation
    - s=Subject, d=Device, n=Network, o=Object, r=Request
    - Test cases:
        * Full access: CEO from Production accessing employees (ALLOW)
        * Insufficient trust: Analyst from unknown external accessing
          audit resource (DENY - trust 77 < required 80)
        * Blacklisted IP: Even CEO from blacklisted IP (DENY immediately)
    - Demonstrates: Complete Zero Trust decision flow

SECTION 8: Network Segmentation Impact
    - Shows how the same user gets different trust scores based on network
    - Compares Developer (f.colombo) trust from:
        * Production Network: +30 context bonus
        * Development Network: +25 context bonus
        * Internal Network: +20 context bonus
        * DMZ Network: +15 context bonus
        * External Whitelisted: -15 context penalty
    - Demonstrates: Network location affects trust level


EXPECTED OUTPUT
---------------
If all services are running correctly:

    Total Tests: 30
    Passed: 30
    Failed: 0

    ============================================
       ALL TESTS PASSED - ZTA Working Correctly
    ============================================


TROUBLESHOOTING
---------------
If tests fail:

1. Services not ready:
   - Wait 2-3 minutes after docker-compose up
   - Check: docker-compose ps (all should be "Up" or "healthy")

2. Keycloak authentication fails:
   - Verify keycloak-init completed: docker logs keycloak-init
   - Check Keycloak is accessible: curl http://localhost:8180/realms/techcorp

3. Database connection fails:
   - Check PostgreSQL: docker logs postgres-db
   - Verify port 5432 is accessible

4. IDS tests fail:
   - Check Snort is running: curl http://localhost:9090/health
   - View Snort logs: docker logs snort-ids


ZERO TRUST PRINCIPLES DEMONSTRATED
----------------------------------
1. NEVER TRUST, ALWAYS VERIFY
   - Every request is authenticated (Keycloak JWT)
   - Every request is authorized (PDP evaluation)
   - No implicit trust based on network location alone

2. LEAST PRIVILEGE ACCESS
   - Users only access resources their role permits
   - Actions (read/write/delete) are role-restricted
   - Sensitive resources (audit) require higher trust + specific roles

3. ASSUME BREACH
   - Multiple security layers (IPTables -> Squid -> Snort -> PEP -> PDP)
   - IDS monitors all traffic for attack patterns
   - All decisions logged to SIEM for audit trail

4. CONTINUOUS VERIFICATION
   - Trust score calculated on EVERY request
   - Historical behavior affects current trust (SIEM integration)
   - Anomalies reduce trust score dynamically


ADDITIONAL RESOURCES
--------------------
After running tests, you can explore:

- Splunk SIEM Dashboard: http://localhost:8000
  Login: admin / TechCorp2024!

- Keycloak Admin Console: http://localhost:8180/admin
  Login: admin / TechCorp2024!

- View IDS Rules:
  curl http://localhost:9090/rules | python3 -m json.tool

- View Firewall Status:
  curl http://localhost:8888/status | python3 -m json.tool

- View PDP Policies:
  curl http://localhost:5000/policies | python3 -m json.tool


TEST USERS AVAILABLE
--------------------
| Username    | Role          | Password      |
|-------------|---------------|---------------|
| m.rossi     | CEO           | Ceo2024!      |
| l.bianchi   | CTO           | Cto2024!      |
| g.ferrari   | HR Manager    | Hr2024!       |
| a.romano    | Sales Manager | Sales2024!    |
| f.colombo   | Developer     | Dev2024!      |
| s.ricci     | Analyst       | Analyst2024!  |


NETWORK CONFIGURATION
---------------------
| Network       | Subnet          | Trust Bonus |
|---------------|-----------------|-------------|
| Production    | 172.28.4.0/24   | +30         |
| Development   | 172.28.5.0/24   | +25         |
| Internal      | 172.28.2.0/24   | +20         |
| DMZ           | 172.28.3.0/24   | +15         |
| External WL   | 172.28.1.100    | -15         |
| External      | 172.28.1.x      | -40         |
| Blacklisted   | 172.28.1.200    | BLOCKED     |


================================================================================
                         End of Instructions
================================================================================

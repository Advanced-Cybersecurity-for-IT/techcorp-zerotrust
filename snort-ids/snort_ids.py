"""
============================================================================
SNORT IDS - Intrusion Detection System Simulator
Zero Trust Architecture - TechCorp
============================================================================
Simula un Network Intrusion Detection System (NIDS) che:
1. Analizza il traffico di rete in tempo reale
2. Applica regole di detection (signature-based)
3. Genera alert per attività sospette
4. Invia tutti i log al SIEM (Splunk)
============================================================================
"""

import os
import json
import logging
import hashlib
import re
from datetime import datetime
from flask import Flask, request, jsonify
import requests
from threading import Lock

# Configurazione logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [SNORT-IDS] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================================
# CONFIGURAZIONE
# ============================================================================
SPLUNK_HOST = os.environ.get('SPLUNK_HOST', 'splunk')
SPLUNK_HEC_TOKEN = os.environ.get('SPLUNK_HEC_TOKEN', 'techcorp-hec-token-2024')
IDS_MODE = os.environ.get('IDS_MODE', 'inline')  # inline, passive, tap

# Thread-safe counters
stats_lock = Lock()
stats = {
    'packets_analyzed': 0,
    'alerts_generated': 0,
    'blocked_attempts': 0,
    'sessions_tracked': 0
}

# ============================================================================
# SNORT RULES DATABASE
# ============================================================================
SNORT_RULES = {
    # -------------------------------------------------------------------------
    # NETWORK SCAN DETECTION
    # -------------------------------------------------------------------------
    'SCAN-001': {
        'name': 'Port Scan Detection',
        'description': 'Detects rapid port scanning activity',
        'severity': 'medium',
        'category': 'reconnaissance',
        'pattern': r'scan|nmap|masscan',
        'threshold': 10,  # requests in timeframe
        'action': 'alert'
    },
    'SCAN-002': {
        'name': 'Vulnerability Scanner Detection',
        'description': 'Detects common vulnerability scanners',
        'severity': 'high',
        'category': 'reconnaissance',
        'pattern': r'nikto|nessus|openvas|acunetix|burp',
        'action': 'alert'
    },
    
    # -------------------------------------------------------------------------
    # SQL INJECTION DETECTION
    # -------------------------------------------------------------------------
    'SQLI-001': {
        'name': 'SQL Injection Attempt - UNION',
        'description': 'Detects UNION-based SQL injection',
        'severity': 'critical',
        'category': 'injection',
        'pattern': r'union\s+(all\s+)?select|select\s+.*\s+from',
        'action': 'block'
    },
    'SQLI-002': {
        'name': 'SQL Injection Attempt - Boolean',
        'description': 'Detects boolean-based SQL injection',
        'severity': 'critical',
        'category': 'injection',
        'pattern': r"('\s*(or|and)\s*'?[0-9]+'?\s*=\s*'?[0-9]+'?)|(--)|(;--)",
        'action': 'block'
    },
    'SQLI-003': {
        'name': 'SQL Injection Attempt - Time-based',
        'description': 'Detects time-based blind SQL injection',
        'severity': 'critical',
        'category': 'injection',
        'pattern': r'sleep\s*\(|benchmark\s*\(|waitfor\s+delay',
        'action': 'block'
    },
    
    # -------------------------------------------------------------------------
    # XSS DETECTION
    # -------------------------------------------------------------------------
    'XSS-001': {
        'name': 'Cross-Site Scripting - Script Tag',
        'description': 'Detects script tag injection',
        'severity': 'high',
        'category': 'xss',
        'pattern': r'<script[^>]*>|javascript:|on\w+\s*=',
        'action': 'block'
    },
    'XSS-002': {
        'name': 'Cross-Site Scripting - Event Handler',
        'description': 'Detects event handler injection',
        'severity': 'high',
        'category': 'xss',
        'pattern': r'onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=',
        'action': 'block'
    },
    
    # -------------------------------------------------------------------------
    # PATH TRAVERSAL DETECTION
    # -------------------------------------------------------------------------
    'TRAV-001': {
        'name': 'Directory Traversal Attempt',
        'description': 'Detects path traversal attacks',
        'severity': 'high',
        'category': 'traversal',
        'pattern': r'\.\./|\.\.\\|%2e%2e%2f|%2e%2e/',
        'action': 'block'
    },
    'TRAV-002': {
        'name': 'Sensitive File Access Attempt',
        'description': 'Detects attempts to access sensitive files',
        'severity': 'critical',
        'category': 'traversal',
        'pattern': r'/etc/passwd|/etc/shadow|\.htaccess|web\.config',
        'action': 'block'
    },
    
    # -------------------------------------------------------------------------
    # COMMAND INJECTION DETECTION
    # -------------------------------------------------------------------------
    'CMD-001': {
        'name': 'Command Injection Attempt',
        'description': 'Detects OS command injection',
        'severity': 'critical',
        'category': 'injection',
        'pattern': r';\s*(ls|cat|wget|curl|nc|bash|sh|python|perl|ruby)',
        'action': 'block'
    },
    'CMD-002': {
        'name': 'Shell Metacharacter Injection',
        'description': 'Detects shell metacharacter abuse',
        'severity': 'high',
        'category': 'injection',
        'pattern': r'\|.*\||`.*`|\$\(.*\)',
        'action': 'alert'
    },
    
    # -------------------------------------------------------------------------
    # MALICIOUS USER AGENT DETECTION
    # -------------------------------------------------------------------------
    'UA-001': {
        'name': 'Malicious Bot Detection',
        'description': 'Detects known malicious bots and crawlers',
        'severity': 'medium',
        'category': 'bot',
        'pattern': r'sqlmap|havij|pangolin|webscarab|paros',
        'action': 'block'
    },
    'UA-002': {
        'name': 'Suspicious User Agent',
        'description': 'Detects suspicious or empty user agents',
        'severity': 'low',
        'category': 'bot',
        'pattern': r'^$|^-$|curl/|wget/|python-requests',
        'action': 'alert'
    },
    
    # -------------------------------------------------------------------------
    # BRUTE FORCE DETECTION
    # -------------------------------------------------------------------------
    'BRUTE-001': {
        'name': 'Login Brute Force Attempt',
        'description': 'Detects multiple failed login attempts',
        'severity': 'high',
        'category': 'brute_force',
        'threshold': 5,
        'timeframe': 60,
        'action': 'block'
    },
    
    # -------------------------------------------------------------------------
    # DATA EXFILTRATION DETECTION
    # -------------------------------------------------------------------------
    'EXFIL-001': {
        'name': 'Large Data Transfer',
        'description': 'Detects unusually large data transfers',
        'severity': 'medium',
        'category': 'exfiltration',
        'threshold_bytes': 10485760,  # 10MB
        'action': 'alert'
    },
    
    # -------------------------------------------------------------------------
    # PROTOCOL ANOMALY DETECTION
    # -------------------------------------------------------------------------
    'PROTO-001': {
        'name': 'HTTP Method Anomaly',
        'description': 'Detects unusual HTTP methods',
        'severity': 'medium',
        'category': 'anomaly',
        'pattern': r'^(TRACE|TRACK|CONNECT|DEBUG)$',
        'action': 'alert'
    }
}

# Tracked sessions for stateful analysis
tracked_sessions = {}

# ============================================================================
# SIEM LOGGING
# ============================================================================
def log_to_siem(event_data):
    """Invia evento al SIEM (Splunk)"""
    try:
        hec_url = f"https://{SPLUNK_HOST}:8088/services/collector/event"
        headers = {
            'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',
            'Content-Type': 'application/json'
        }
        payload = {
            'event': event_data,
            'index': 'zerotrust',
            'sourcetype': 'snort_ids'
        }
        requests.post(hec_url, headers=headers, json=payload, verify=False, timeout=5)
        logger.info(f"Event logged to SIEM: {event_data.get('rule_id', 'unknown')}")
    except Exception as e:
        logger.warning(f"Failed to log to SIEM: {e}")

# ============================================================================
# PACKET ANALYSIS ENGINE
# ============================================================================
def analyze_packet(packet_data):
    """
    Analizza un pacchetto/richiesta per pattern malevoli
    
    Input: {
        "source_ip": "...",
        "dest_ip": "...",
        "source_port": int,
        "dest_port": int,
        "protocol": "TCP|UDP|HTTP",
        "payload": "...",
        "headers": {...},
        "method": "GET|POST|...",
        "uri": "...",
        "user_agent": "..."
    }
    """
    alerts = []
    source_ip = packet_data.get('source_ip', 'unknown')
    payload = packet_data.get('payload', '')
    uri = packet_data.get('uri', '')
    user_agent = packet_data.get('user_agent', '')
    method = packet_data.get('method', 'GET')
    
    # Combine all text fields for analysis
    combined_text = f"{payload} {uri} {user_agent}".lower()
    
    with stats_lock:
        stats['packets_analyzed'] += 1
    
    # -------------------------------------------------------------------------
    # SIGNATURE-BASED DETECTION
    # -------------------------------------------------------------------------
    for rule_id, rule in SNORT_RULES.items():
        if 'pattern' in rule:
            try:
                if re.search(rule['pattern'], combined_text, re.IGNORECASE):
                    alert = create_alert(rule_id, rule, packet_data)
                    alerts.append(alert)
                    log_to_siem(alert)
                    
                    with stats_lock:
                        stats['alerts_generated'] += 1
                        if rule['action'] == 'block':
                            stats['blocked_attempts'] += 1
            except re.error as e:
                logger.error(f"Regex error in rule {rule_id}: {e}")
    
    # -------------------------------------------------------------------------
    # HTTP METHOD ANOMALY
    # -------------------------------------------------------------------------
    if method.upper() in ['TRACE', 'TRACK', 'CONNECT', 'DEBUG']:
        rule = SNORT_RULES['PROTO-001']
        alert = create_alert('PROTO-001', rule, packet_data)
        alerts.append(alert)
        log_to_siem(alert)
    
    # -------------------------------------------------------------------------
    # SESSION TRACKING (Stateful Analysis)
    # -------------------------------------------------------------------------
    session_key = f"{source_ip}:{packet_data.get('dest_ip', '')}"
    if session_key not in tracked_sessions:
        tracked_sessions[session_key] = {
            'request_count': 0,
            'first_seen': datetime.now().isoformat(),
            'failed_logins': 0
        }
        with stats_lock:
            stats['sessions_tracked'] += 1
    
    tracked_sessions[session_key]['request_count'] += 1
    tracked_sessions[session_key]['last_seen'] = datetime.now().isoformat()
    
    return alerts

def create_alert(rule_id, rule, packet_data):
    """Crea un alert strutturato"""
    return {
        'timestamp': datetime.now().isoformat(),
        'rule_id': rule_id,
        'rule_name': rule['name'],
        'description': rule['description'],
        'severity': rule['severity'],
        'category': rule['category'],
        'action': rule['action'],
        'source_ip': packet_data.get('source_ip', 'unknown'),
        'dest_ip': packet_data.get('dest_ip', 'unknown'),
        'source_port': packet_data.get('source_port', 0),
        'dest_port': packet_data.get('dest_port', 0),
        'protocol': packet_data.get('protocol', 'unknown'),
        'uri': packet_data.get('uri', ''),
        'method': packet_data.get('method', ''),
        'user_agent': packet_data.get('user_agent', ''),
        'payload_hash': hashlib.md5(
            packet_data.get('payload', '').encode()
        ).hexdigest()[:16] if packet_data.get('payload') else None
    }

# ============================================================================
# DEEP PACKET INSPECTION
# ============================================================================
def deep_inspection(packet_data):
    """
    Esegue Deep Packet Inspection per analisi avanzata
    """
    results = {
        'anomalies': [],
        'risk_score': 0,
        'recommendations': []
    }
    
    payload = packet_data.get('payload', '')
    
    # Check for encoded payloads
    if '%' in payload or '&#' in payload:
        results['anomalies'].append('Encoded payload detected')
        results['risk_score'] += 20
    
    # Check for base64 encoded content
    if re.search(r'^[A-Za-z0-9+/]{50,}={0,2}$', payload):
        results['anomalies'].append('Possible base64 encoded payload')
        results['risk_score'] += 15
    
    # Check for unusual characters
    if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', payload):
        results['anomalies'].append('Binary/control characters in payload')
        results['risk_score'] += 25
    
    # Check payload entropy (high entropy = possible encryption/obfuscation)
    if len(payload) > 100:
        entropy = calculate_entropy(payload)
        if entropy > 5.5:
            results['anomalies'].append(f'High entropy payload ({entropy:.2f})')
            results['risk_score'] += 30
    
    return results

def calculate_entropy(data):
    """Calcola l'entropia di Shannon dei dati"""
    if not data:
        return 0
    
    from collections import Counter
    import math
    
    counter = Counter(data)
    length = len(data)
    
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

# ============================================================================
# API ENDPOINTS
# ============================================================================
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Snort-IDS',
        'mode': IDS_MODE,
        'timestamp': datetime.now().isoformat(),
        'stats': stats
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Endpoint principale per analisi pacchetti
    Riceve pacchetti/richieste da firewall o altri componenti
    """
    try:
        packet_data = request.get_json()
        if not packet_data:
            return jsonify({'error': 'No packet data provided'}), 400
        
        alerts = analyze_packet(packet_data)
        
        # Determine if traffic should be blocked
        blocked = any(a['action'] == 'block' for a in alerts)
        
        response = {
            'analyzed': True,
            'alerts_count': len(alerts),
            'alerts': alerts,
            'blocked': blocked,
            'timestamp': datetime.now().isoformat()
        }
        
        # Log the analysis result
        log_to_siem({
            'type': 'analysis_result',
            'source_ip': packet_data.get('source_ip'),
            'alerts_count': len(alerts),
            'blocked': blocked,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/deep-inspect', methods=['POST'])
def deep_inspect():
    """Deep Packet Inspection endpoint"""
    try:
        packet_data = request.get_json()
        if not packet_data:
            return jsonify({'error': 'No packet data provided'}), 400
        
        # Run both standard analysis and deep inspection
        alerts = analyze_packet(packet_data)
        dpi_results = deep_inspection(packet_data)
        
        return jsonify({
            'alerts': alerts,
            'dpi_results': dpi_results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Deep inspection error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/rules', methods=['GET'])
def get_rules():
    """Restituisce le regole attive"""
    return jsonify({
        'rules_count': len(SNORT_RULES),
        'rules': SNORT_RULES
    })

@app.route('/rules/<rule_id>', methods=['GET'])
def get_rule(rule_id):
    """Restituisce una specifica regola"""
    rule = SNORT_RULES.get(rule_id)
    if rule:
        return jsonify({'rule_id': rule_id, **rule})
    return jsonify({'error': 'Rule not found'}), 404

@app.route('/stats', methods=['GET'])
def get_stats():
    """Restituisce le statistiche IDS"""
    with stats_lock:
        return jsonify({
            **stats,
            'active_sessions': len(tracked_sessions),
            'uptime': datetime.now().isoformat()
        })

@app.route('/sessions', methods=['GET'])
def get_sessions():
    """Restituisce le sessioni tracciate"""
    return jsonify({
        'session_count': len(tracked_sessions),
        'sessions': tracked_sessions
    })

@app.route('/test-attack', methods=['POST'])
def test_attack():
    """
    Endpoint per testare la detection con payload malevoli simulati
    Utile per demo e testing
    """
    attack_type = request.json.get('type', 'sqli')
    
    test_payloads = {
        'sqli': {
            'payload': "' OR '1'='1",
            'uri': "/api/users?id=1' UNION SELECT * FROM users--",
            'method': 'GET'
        },
        'xss': {
            'payload': '<script>alert("XSS")</script>',
            'uri': '/search?q=<script>document.cookie</script>',
            'method': 'GET'
        },
        'traversal': {
            'payload': '',
            'uri': '/files/../../../etc/passwd',
            'method': 'GET'
        },
        'cmdi': {
            'payload': '; cat /etc/passwd',
            'uri': '/api/ping?host=localhost;ls -la',
            'method': 'POST'
        },
        'scan': {
            'payload': '',
            'uri': '/admin',
            'method': 'GET',
            'user_agent': 'Nikto/2.1.6'
        }
    }
    
    test_data = test_payloads.get(attack_type, test_payloads['sqli'])
    test_data['source_ip'] = request.remote_addr or '192.168.1.100'
    test_data['dest_ip'] = '172.28.2.40'
    test_data['protocol'] = 'HTTP'
    
    alerts = analyze_packet(test_data)
    
    return jsonify({
        'test_type': attack_type,
        'detected': len(alerts) > 0,
        'alerts': alerts
    })

# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("SNORT IDS - Intrusion Detection System")
    logger.info("Zero Trust Architecture - TechCorp")
    logger.info("=" * 60)
    logger.info(f"Mode: {IDS_MODE}")
    logger.info(f"Rules loaded: {len(SNORT_RULES)}")
    logger.info(f"SIEM: {SPLUNK_HOST}")
    
    app.run(host='0.0.0.0', port=9090, debug=False)

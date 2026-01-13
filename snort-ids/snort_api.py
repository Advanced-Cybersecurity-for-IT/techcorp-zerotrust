#!/usr/bin/env python3
"""
============================================================================
SNORT IDS - Python API Wrapper
TechCorp Zero Trust Architecture
============================================================================
This wrapper provides an HTTP API interface to the real Snort IDS engine.
It receives packet data from PEP, creates pcap files using scapy,
runs Snort for analysis, and returns alerts in JSON format.
============================================================================
"""

import os
import json
import logging
import tempfile
import subprocess
import re
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify
from threading import Lock
import requests

# Scapy imports
from scapy.all import IP, TCP, Raw, wrpcap, Ether

# Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s [SNORT-API] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
SNORT_BIN = os.environ.get('SNORT_BIN', '/usr/sbin/snort')
SNORT_CONF = os.environ.get('SNORT_CONF', '/etc/snort/snort.conf')
SPLUNK_HOST = os.environ.get('SPLUNK_HOST', 'splunk')
SPLUNK_HEC_TOKEN = os.environ.get('SPLUNK_HEC_TOKEN', 'techcorp-hec-token-2024')
IDS_MODE = os.environ.get('IDS_MODE', 'inline')

# Thread-safe statistics
stats_lock = Lock()
stats = {
    'packets_analyzed': 0,
    'alerts_generated': 0,
    'blocked_attempts': 0,
    'snort_invocations': 0,
    'start_time': datetime.now().isoformat()
}

# Cache for tracking sessions
tracked_sessions = {}

# ============================================================================
# SIEM LOGGING
# ============================================================================
def log_to_siem(event_data):
    """Send event to SIEM (Splunk)"""
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
    except Exception as e:
        logger.warning(f"Failed to log to SIEM: {e}")

# ============================================================================
# PCAP GENERATION
# ============================================================================
def create_pcap_from_request(packet_data, pcap_path):
    """
    Create a pcap file from HTTP request data using scapy.
    This allows Snort to analyze the payload using its rules.
    """
    source_ip = packet_data.get('source_ip', '192.168.1.100')
    dest_ip = packet_data.get('dest_ip', '172.28.2.40')
    source_port = packet_data.get('source_port', 12345)
    dest_port = packet_data.get('dest_port', 80)

    # Build HTTP request payload
    method = packet_data.get('method', 'GET')
    # Support both 'uri' and 'path' parameters
    uri = packet_data.get('uri') or packet_data.get('path', '/')
    # Get user_agent from direct parameter or from headers
    headers = packet_data.get('headers', {})
    user_agent = packet_data.get('user_agent') or headers.get('User-Agent', 'Mozilla/5.0')
    # Support both 'payload' and 'body' parameters
    payload_body = packet_data.get('payload') or packet_data.get('body', '')

    # Construct HTTP request
    http_request = f"{method} {uri} HTTP/1.1\r\n"
    http_request += f"Host: {dest_ip}\r\n"
    http_request += f"User-Agent: {user_agent}\r\n"

    # Add other headers if present (headers already retrieved above)
    for key, value in headers.items():
        if key.lower() not in ['host', 'user-agent']:
            http_request += f"{key}: {value}\r\n"

    http_request += "\r\n"

    # Add body if present
    if payload_body:
        http_request += payload_body

    # Create packet with scapy
    # Ethernet + IP + TCP + HTTP payload
    packet = Ether()/IP(src=source_ip, dst=dest_ip)/TCP(sport=source_port, dport=dest_port, flags='PA')/Raw(load=http_request.encode())

    # Write to pcap file
    wrpcap(pcap_path, packet)

    return http_request

# ============================================================================
# SNORT ANALYSIS
# ============================================================================
def run_snort_analysis(pcap_path):
    """
    Run Snort on a pcap file and parse the alerts.
    Returns list of alerts found.
    """
    alerts = []
    alert_file = tempfile.mktemp(suffix='.alert')

    try:
        # Run Snort in read mode on the pcap file
        # -r: read pcap file
        # -c: config file
        # -A: alert mode (fast)
        # -l: log directory
        # -q: quiet mode
        cmd = [
            SNORT_BIN,
            '-r', pcap_path,
            '-c', SNORT_CONF,
            '-A', 'fast',
            '-l', '/tmp',
            '-q',
            '--daq', 'pcap',
            '--daq-mode', 'read-file'
        ]

        logger.info(f"Running Snort: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        with stats_lock:
            stats['snort_invocations'] += 1

        # Check for alerts in Snort output or alert file
        # Snort outputs alerts to stdout in fast mode
        output = result.stdout + result.stderr

        # Also check the alert file if it exists
        if os.path.exists('/tmp/alert'):
            with open('/tmp/alert', 'r') as f:
                output += f.read()
            # Clear alert file for next run
            os.remove('/tmp/alert')

        # Parse alerts from output
        alerts = parse_snort_alerts(output)

        logger.info(f"Snort analysis complete. Found {len(alerts)} alerts.")

    except subprocess.TimeoutExpired:
        logger.error("Snort analysis timed out")
    except Exception as e:
        logger.error(f"Snort analysis error: {e}")

    return alerts

def parse_snort_alerts(output):
    """
    Parse Snort fast alert format output.
    Format: MM/DD-HH:MM:SS.ssssss  [**] [1:SID:REV] MSG [**] [Classification: CLASS] [Priority: N] {PROTO} SRC -> DST
    """
    alerts = []

    # Pattern for Snort fast alert format
    alert_pattern = r'\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*([^\[]+)\s*\[\*\*\]'
    classification_pattern = r'\[Classification:\s*([^\]]+)\]'
    priority_pattern = r'\[Priority:\s*(\d+)\]'

    for line in output.split('\n'):
        if '[**]' in line:
            match = re.search(alert_pattern, line)
            if match:
                gid, sid, rev = match.groups()[:3]
                msg = match.group(4).strip()

                # Extract classification
                class_match = re.search(classification_pattern, line)
                classification = class_match.group(1) if class_match else 'unknown'

                # Extract priority
                priority_match = re.search(priority_pattern, line)
                priority = int(priority_match.group(1)) if priority_match else 3

                # Determine severity based on priority
                if priority == 1:
                    severity = 'critical'
                elif priority == 2:
                    severity = 'high'
                elif priority == 3:
                    severity = 'medium'
                else:
                    severity = 'low'

                # Determine action based on classification
                action = 'block' if 'attack' in classification.lower() else 'alert'

                # Extract rule ID from message (e.g., "SQLI-001 SQL Injection...")
                rule_id_match = re.match(r'^([A-Z]+-\d+)', msg)
                rule_id = rule_id_match.group(1) if rule_id_match else f"SID-{sid}"

                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'rule_id': rule_id,
                    'sid': sid,
                    'gid': gid,
                    'rev': rev,
                    'msg': msg,
                    'classification': classification,
                    'priority': priority,
                    'severity': severity,
                    'action': action,
                    'raw_alert': line.strip()
                }
                alerts.append(alert)

                with stats_lock:
                    stats['alerts_generated'] += 1
                    if action == 'block':
                        stats['blocked_attempts'] += 1

    return alerts

# ============================================================================
# FALLBACK PATTERN MATCHING
# ============================================================================
def fallback_pattern_analysis(packet_data):
    """
    Fallback pattern matching if Snort fails.
    This ensures we always provide some level of detection.
    """
    alerts = []

    # Combine all text fields for analysis
    payload = packet_data.get('payload', '')
    uri = packet_data.get('uri', '')
    user_agent = packet_data.get('user_agent', '')
    combined = f"{payload} {uri} {user_agent}".lower()

    # Pattern definitions with severity
    patterns = [
        ('SQLI-001', r'union\s+(all\s+)?select', 'SQL Injection - UNION SELECT', 'critical', 'block'),
        ('SQLI-002', r"'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+'?", 'SQL Injection - Boolean', 'critical', 'block'),
        ('SQLI-003', r'(--|;--)', 'SQL Injection - Comment', 'high', 'block'),
        ('XSS-001', r'<script', 'XSS - Script Tag', 'high', 'block'),
        ('XSS-002', r'on(error|load|click)\s*=', 'XSS - Event Handler', 'high', 'block'),
        ('TRAV-001', r'\.\./', 'Path Traversal', 'high', 'block'),
        ('CMD-001', r';\s*(cat|ls|wget|curl)', 'Command Injection', 'critical', 'block'),
        ('SCAN-001', r'(nikto|sqlmap|nmap|acunetix)', 'Scanner Detected', 'medium', 'alert'),
        ('FILE-001', r'/etc/(passwd|shadow)', 'Sensitive File Access', 'critical', 'block'),
    ]

    for rule_id, pattern, msg, severity, action in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            alerts.append({
                'timestamp': datetime.now().isoformat(),
                'rule_id': rule_id,
                'msg': msg,
                'severity': severity,
                'action': action,
                'source': 'fallback_engine'
            })

    return alerts

# ============================================================================
# API ENDPOINTS
# ============================================================================
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    # Check if Snort is available
    snort_available = os.path.exists(SNORT_BIN)

    return jsonify({
        'status': 'healthy' if snort_available else 'degraded',
        'service': 'Snort-IDS',
        'engine': 'Real Snort' if snort_available else 'Fallback',
        'mode': IDS_MODE,
        'timestamp': datetime.now().isoformat(),
        'stats': stats
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Main endpoint for packet analysis.
    Receives packet data from PEP and returns alerts.
    """
    try:
        packet_data = request.get_json()
        if not packet_data:
            return jsonify({'error': 'No packet data provided'}), 400

        with stats_lock:
            stats['packets_analyzed'] += 1

        source_ip = packet_data.get('source_ip', 'unknown')
        logger.info(f"Analyzing packet from {source_ip}")

        alerts = []

        # Create temporary pcap file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            pcap_path = tmp.name

        try:
            # Create pcap from request data
            create_pcap_from_request(packet_data, pcap_path)

            # Run Snort analysis
            alerts = run_snort_analysis(pcap_path)

            # If Snort didn't find anything, try fallback
            if not alerts:
                fallback_alerts = fallback_pattern_analysis(packet_data)
                if fallback_alerts:
                    alerts.extend(fallback_alerts)
                    logger.info(f"Fallback engine found {len(fallback_alerts)} alerts")

        finally:
            # Clean up temp file
            if os.path.exists(pcap_path):
                os.remove(pcap_path)

        # Determine if traffic should be blocked
        blocked = any(a.get('action') == 'block' for a in alerts)

        # Add source/dest info to alerts
        for alert in alerts:
            alert['source_ip'] = source_ip
            alert['dest_ip'] = packet_data.get('dest_ip', 'unknown')
            alert['uri'] = packet_data.get('uri', '')

        response = {
            'analyzed': True,
            'engine': 'snort',
            'alerts_count': len(alerts),
            'alerts': alerts,
            'blocked': blocked,
            'timestamp': datetime.now().isoformat()
        }

        # Log to SIEM
        log_to_siem({
            'type': 'ids_analysis',
            'source_ip': source_ip,
            'alerts_count': len(alerts),
            'blocked': blocked,
            'alerts': [a.get('rule_id') for a in alerts],
            'timestamp': datetime.now().isoformat()
        })

        return jsonify(response)

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': str(e), 'analyzed': False, 'blocked': False}), 500

@app.route('/rules', methods=['GET'])
def get_rules():
    """Return loaded rules information"""
    rules = []
    rules_file = '/etc/snort/rules/local.rules'

    if os.path.exists(rules_file):
        with open(rules_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract msg from rule
                    msg_match = re.search(r'msg:"([^"]+)"', line)
                    sid_match = re.search(r'sid:(\d+)', line)
                    if msg_match and sid_match:
                        rules.append({
                            'sid': sid_match.group(1),
                            'msg': msg_match.group(1)
                        })

    return jsonify({
        'rules_count': len(rules),
        'rules': rules,
        'rules_file': rules_file
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """Return IDS statistics"""
    with stats_lock:
        return jsonify({
            **stats,
            'active_sessions': len(tracked_sessions),
            'uptime': datetime.now().isoformat()
        })

@app.route('/test-attack', methods=['POST'])
def test_attack():
    """Test endpoint with sample attack payloads"""
    attack_type = request.json.get('type', 'sqli') if request.json else 'sqli'

    test_payloads = {
        'sqli': {
            'payload': "' OR '1'='1",
            'uri': "/api/users?id=1' UNION SELECT * FROM users--",
            'method': 'GET',
            'source_ip': '192.168.1.100',
            'dest_ip': '172.28.2.40'
        },
        'xss': {
            'payload': '<script>alert("XSS")</script>',
            'uri': '/search?q=<script>document.cookie</script>',
            'method': 'GET',
            'source_ip': '192.168.1.100',
            'dest_ip': '172.28.2.40'
        },
        'traversal': {
            'payload': '',
            'uri': '/files/../../../etc/passwd',
            'method': 'GET',
            'source_ip': '192.168.1.100',
            'dest_ip': '172.28.2.40'
        },
        'cmdi': {
            'payload': '; cat /etc/passwd',
            'uri': '/api/ping?host=localhost;ls -la',
            'method': 'POST',
            'source_ip': '192.168.1.100',
            'dest_ip': '172.28.2.40'
        }
    }

    test_data = test_payloads.get(attack_type, test_payloads['sqli'])

    # Run analysis on test payload
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
        pcap_path = tmp.name

    try:
        create_pcap_from_request(test_data, pcap_path)
        alerts = run_snort_analysis(pcap_path)

        if not alerts:
            alerts = fallback_pattern_analysis(test_data)
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)

    return jsonify({
        'test_type': attack_type,
        'detected': len(alerts) > 0,
        'alerts_count': len(alerts),
        'alerts': alerts
    })

# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("SNORT IDS - Real Intrusion Detection System")
    logger.info("TechCorp Zero Trust Architecture")
    logger.info("=" * 60)
    logger.info(f"Snort Binary: {SNORT_BIN}")
    logger.info(f"Snort Config: {SNORT_CONF}")
    logger.info(f"Mode: {IDS_MODE}")
    logger.info(f"SIEM: {SPLUNK_HOST}")

    # Check if Snort is available
    if os.path.exists(SNORT_BIN):
        logger.info("Snort engine: AVAILABLE")
    else:
        logger.warning("Snort engine: NOT FOUND - using fallback pattern matching")

    app.run(host='0.0.0.0', port=9090, debug=False)

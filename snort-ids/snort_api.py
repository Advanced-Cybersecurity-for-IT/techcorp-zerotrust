#!/usr/bin/env python3
"""
============================================================================
SNORT IDS - API Python
TechCorp Zero Trust Architecture
============================================================================
Fornisce un'interfaccia API HTTP per Snort IDS.
Riceve dati pacchetto dal PEP, segue Snort per 
l'analisi e restituisce alert in formato JSON.
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

from scapy.all import IP, TCP, Raw, wrpcap, Ether

# Configurazione
logging.basicConfig(level=logging.INFO, format='%(asctime)s [SNORT-API] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================================
# CONFIGURAZIONE
# ============================================================================
SNORT_BIN = os.environ.get('SNORT_BIN', '/usr/sbin/snort')
SNORT_CONF = os.environ.get('SNORT_CONF', '/etc/snort/snort.conf')
SPLUNK_HOST = os.environ.get('SPLUNK_HOST', 'splunk')
SPLUNK_HEC_TOKEN = os.environ.get('SPLUNK_HEC_TOKEN', 'techcorp-hec-token-2024')
IDS_MODE = os.environ.get('IDS_MODE', 'inline')

stats_lock = Lock()
stats = {
    'packets_analyzed': 0,
    'alerts_generated': 0,
    'blocked_attempts': 0,
    'snort_invocations': 0,
    'start_time': datetime.now().isoformat()
}

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
    except Exception as e:
        logger.warning(f"Failed to log to SIEM: {e}")

# ============================================================================
# GENERAZIONE PCAP
# ============================================================================
def create_pcap_from_request(packet_data, pcap_path):
    """
    Crea un file pcap dai dati della richiesta HTTP usando scapy.
    Questo permette a Snort di analizzare il payload usando le sue regole.
    """
    source_ip = packet_data.get('source_ip', '192.168.1.100')
    dest_ip = packet_data.get('dest_ip', '172.28.2.40')
    source_port = packet_data.get('source_port', 12345)
    dest_port = packet_data.get('dest_port', 80)

    # Costruisce payload richiesta HTTP
    method = packet_data.get('method', 'GET')
 
    uri = packet_data.get('uri') or packet_data.get('path', '/')
    # Ottiene user_agent
    headers = packet_data.get('headers', {})
    user_agent = packet_data.get('user_agent') or headers.get('User-Agent', 'Mozilla/5.0')
    
    payload_body = packet_data.get('payload') or packet_data.get('body', '')

    # Costruisce richiesta HTTP
    http_request = f"{method} {uri} HTTP/1.1\r\n"
    http_request += f"Host: {dest_ip}\r\n"
    http_request += f"User-Agent: {user_agent}\r\n"

    # Aggiunge altri header presenti
    for key, value in headers.items():
        if key.lower() not in ['host', 'user-agent']:
            http_request += f"{key}: {value}\r\n"

    http_request += "\r\n"

    # Aggiunge corpo
    if payload_body:
        http_request += payload_body

    # Crea pacchetto
    packet = Ether()/IP(src=source_ip, dst=dest_ip)/TCP(sport=source_port, dport=dest_port, flags='PA')/Raw(load=http_request.encode())

    # Scrive su file pcap
    wrpcap(pcap_path, packet)

    return http_request

# ============================================================================
# ANALISI SNORT
# ============================================================================
def run_snort_analysis(pcap_path):
    """
    Esegue Snort su un file pcap e analizza gli alert.
    Restituisce lista degli alert trovati.
    """
    alerts = []
    alert_file = tempfile.mktemp(suffix='.alert')

    try:
        # Esegue Snort in modalità lettura sul file pcap
        # -r: legge file pcap
        # -c: file config
        # -A: modalità alert
        # -l: directory log
        # -q: modalità silenziosa
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

        # Controlla alert in output
        output = result.stdout + result.stderr

        # Controlla file alert
        if os.path.exists('/tmp/alert'):
            with open('/tmp/alert', 'r') as f:
                output += f.read()
            # Pulisce file alert
            os.remove('/tmp/alert')

        # Analizza alert dall'output
        alerts = parse_snort_alerts(output)

        logger.info(f"Snort analysis complete. Found {len(alerts)} alerts.")

    except subprocess.TimeoutExpired:
        logger.error("Snort analysis timed out")
    except Exception as e:
        logger.error(f"Snort analysis error: {e}")

    return alerts

def parse_snort_alerts(output):
    """
    Analizza output formato fast alert di Snort.
    Format: MM/DD-HH:MM:SS.ssssss  [**] [1:SID:REV] MSG [**] [Classification: CLASS] [Priority: N] {PROTO} SRC -> DST
    """
    alerts = []

    # Formato fast alert
    alert_pattern = r'\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*([^\[]+)\s*\[\*\*\]'
    classification_pattern = r'\[Classification:\s*([^\]]+)\]'
    priority_pattern = r'\[Priority:\s*(\d+)\]'

    for line in output.split('\n'):
        if '[**]' in line:
            match = re.search(alert_pattern, line)
            if match:
                gid, sid, rev = match.groups()[:3]
                msg = match.group(4).strip()

                # Estrae classificazione
                class_match = re.search(classification_pattern, line)
                classification = class_match.group(1) if class_match else 'unknown'

                # Estrae priorita'
                priority_match = re.search(priority_pattern, line)
                priority = int(priority_match.group(1)) if priority_match else 3

                # Determina gravita' basata su priorita'
                if priority == 1:
                    severity = 'critical'
                elif priority == 2:
                    severity = 'high'
                elif priority == 3:
                    severity = 'medium'
                else:
                    severity = 'low'

                # Determina azione basata su classificazione
                action = 'block' if 'attack' in classification.lower() else 'alert'

                # Estrae ID regola
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
    Pattern matching di fallback se Snort fallisce
    Assicura sempre un certo livello di rilevamento
    """
    alerts = []

    payload = packet_data.get('payload', '')
    uri = packet_data.get('uri', '')
    user_agent = packet_data.get('user_agent', '')
    combined = f"{payload} {uri} {user_agent}".lower()

    # Definizioni pattern con gravita'
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
    """Endpoint Health check"""
    # Controlla disponibilita' Snort
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
    Endpoint principale per analisi pacchetti
    Riceve dati pacchetto dal PEP e restituisce alert
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

        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            pcap_path = tmp.name

        try:
            # Crea pcap dai dati della richiesta
            create_pcap_from_request(packet_data, pcap_path)

            # Esegue analisi Snort
            alerts = run_snort_analysis(pcap_path)

            # Prova fallback se Snort non restituisce alert
            if not alerts:
                fallback_alerts = fallback_pattern_analysis(packet_data)
                if fallback_alerts:
                    alerts.extend(fallback_alerts)
                    logger.info(f"Fallback engine found {len(fallback_alerts)} alerts")

        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)

        # Determina se il traffico deve essere bloccato
        blocked = any(a.get('action') == 'block' for a in alerts)

        # Aggiunge info su sorgente e destinazione agli alert
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

        # Log su Splunk
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
    """Restituisce informazioni su regole caricate"""
    rules = []
    rules_file = '/etc/snort/rules/local.rules'

    if os.path.exists(rules_file):
        with open(rules_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Estrae msg dalla regola
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
    """Restituisce statistiche IDS"""
    with stats_lock:
        return jsonify({
            **stats,
            'active_sessions': len(tracked_sessions),
            'uptime': datetime.now().isoformat()
        })

@app.route('/test-attack', methods=['POST'])
def test_attack():
    """Endpoint di test"""
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

    # Esegue analisi su payload di test
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

    if os.path.exists(SNORT_BIN):
        logger.info("Snort engine: AVAILABLE")
    else:
        logger.warning("Snort engine: NOT FOUND - using fallback pattern matching")

    app.run(host='0.0.0.0', port=9090, debug=False)

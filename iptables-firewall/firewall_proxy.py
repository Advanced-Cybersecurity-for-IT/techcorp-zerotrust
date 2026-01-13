#!/usr/bin/env python3
"""
IPTABLES FIREWALL - HTTP Proxy with Real-IP Preservation
TechCorp Zero Trust Architecture

This script:
1. Acts as an HTTP reverse proxy to Squid (L7 firewall)
2. Preserves original client IP via X-Real-IP header
3. Provides status/monitoring endpoints
4. Works in conjunction with iptables rules for network-level blocking

Traffic flow: External Host -> iptables (L3) -> Squid (L7) -> PEP

Note: Blacklisted IPs are blocked by iptables at the network level
before they can even reach this proxy.
"""

import os
import json
import socket
import subprocess
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import http.client

# Configuration from environment - Forward to Squid (L7) instead of PEP
UPSTREAM_IP = os.environ.get('UPSTREAM_IP', '172.28.3.5')
UPSTREAM_PORT = int(os.environ.get('UPSTREAM_PORT', 3128))
LISTEN_PORT = int(os.environ.get('LISTEN_PORT', 8080))
STATUS_PORT = int(os.environ.get('STATUS_PORT', 8888))

BLACKLIST = os.environ.get('BLACKLIST', '172.28.1.200 172.28.1.250 172.28.1.60').split()
WHITELIST = os.environ.get('WHITELIST', '172.28.1.100 172.28.1.50').split()

# Statistics
stats = {
    'requests_forwarded': 0,
    'requests_blocked': 0,
    'bytes_transferred': 0,
    'start_time': datetime.now().isoformat(),
    'last_request': None,
    'blocked_attempts': []
}
stats_lock = threading.Lock()


def log(message, level='INFO'):
    """Logging with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] {message}")


def get_client_ip(handler):
    """Extract client IP from connection"""
    client_ip = handler.client_address[0]
    # Remove IPv6 prefix if present
    if client_ip.startswith('::ffff:'):
        client_ip = client_ip[7:]
    return client_ip


def get_iptables_rules():
    """Get current iptables rules"""
    try:
        result = subprocess.check_output(
            ['iptables', '-L', 'INPUT', '-n', '-v', '--line-numbers'],
            stderr=subprocess.STDOUT
        ).decode('utf-8')
        return result
    except Exception as e:
        return f"Error: {e}"


def get_iptables_stats():
    """Parse iptables statistics"""
    try:
        output = subprocess.check_output(
            ['iptables', '-L', 'INPUT', '-n', '-v', '-x'],
            stderr=subprocess.STDOUT
        ).decode('utf-8')

        blocked = 0
        for line in output.split('\n'):
            if 'DROP' in line and any(ip in line for ip in BLACKLIST):
                parts = line.split()
                if len(parts) >= 1 and parts[0].isdigit():
                    blocked += int(parts[0])

        return {'iptables_blocked_packets': blocked}
    except Exception as e:
        return {'error': str(e)}


# ============================================================================
# HTTP Proxy Handler
# ============================================================================
class ProxyHandler(BaseHTTPRequestHandler):
    """Reverse proxy that forwards requests to PEP with X-Real-IP header"""

    def log_message(self, format, *args):
        """Custom logging"""
        client_ip = get_client_ip(self)
        log(f"[PROXY] {client_ip} - {format % args}")

    def do_proxy(self):
        """Forward request to PEP"""
        client_ip = get_client_ip(self)

        # Note: If we reach here, the client passed iptables filtering
        # (blacklisted IPs are DROPped at network level)

        try:
            # Read request body if present
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            # Connect to Squid (upstream L7 firewall)
            conn = http.client.HTTPConnection(UPSTREAM_IP, UPSTREAM_PORT, timeout=30)

            # Build headers, adding X-Real-IP
            headers = {}
            for key, value in self.headers.items():
                # Skip hop-by-hop headers
                if key.lower() not in ['connection', 'keep-alive', 'transfer-encoding']:
                    headers[key] = value

            # Add/override IP headers for PEP to know original client
            headers['X-Real-IP'] = client_ip
            headers['X-Forwarded-For'] = client_ip
            headers['X-Forwarded-Proto'] = 'http'
            headers['X-Forwarded-By'] = 'iptables-firewall'

            # Forward request
            conn.request(self.command, self.path, body=body, headers=headers)

            # Get response
            response = conn.getresponse()
            response_body = response.read()

            # Send response back to client
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response_body)

            # Update statistics
            with stats_lock:
                stats['requests_forwarded'] += 1
                stats['bytes_transferred'] += len(response_body)
                stats['last_request'] = {
                    'time': datetime.now().isoformat(),
                    'client_ip': client_ip,
                    'path': self.path,
                    'status': response.status
                }

            log(f"[FORWARD] {client_ip} -> Squid(L7): {self.command} {self.path} -> {response.status}")
            conn.close()

        except Exception as e:
            log(f"[ERROR] Proxy error for {client_ip}: {e}", 'ERROR')
            self.send_error(502, f"Bad Gateway: {e}")
            with stats_lock:
                stats['requests_blocked'] += 1

    def do_GET(self):
        self.do_proxy()

    def do_POST(self):
        self.do_proxy()

    def do_PUT(self):
        self.do_proxy()

    def do_DELETE(self):
        self.do_proxy()

    def do_OPTIONS(self):
        self.do_proxy()

    def do_HEAD(self):
        self.do_proxy()


# ============================================================================
# Status API Handler
# ============================================================================
class StatusHandler(BaseHTTPRequestHandler):
    """Status and monitoring API"""

    def log_message(self, *args):
        pass  # Suppress default logging

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def do_GET(self):
        if self.path == '/health':
            self.send_json({
                'status': 'healthy',
                'service': 'iptables-firewall',
                'mode': 'network-level + proxy',
                'timestamp': datetime.now().isoformat()
            })

        elif self.path == '/status':
            with stats_lock:
                current_stats = dict(stats)

            self.send_json({
                'status': 'active',
                'service': 'iptables-firewall',
                'mode': 'network-level filtering + HTTP proxy',
                'configuration': {
                    'upstream_target': f'{UPSTREAM_IP}:{UPSTREAM_PORT}',
                    'upstream_service': 'Squid (Layer 7)',
                    'listen_port': LISTEN_PORT,
                    'blacklist': BLACKLIST,
                    'whitelist': WHITELIST
                },
                'statistics': {
                    **current_stats,
                    **get_iptables_stats()
                },
                'timestamp': datetime.now().isoformat()
            })

        elif self.path == '/rules':
            self.send_json({
                'iptables_rules': get_iptables_rules(),
                'description': 'Blacklisted IPs are blocked at network level (INPUT chain DROP)',
                'timestamp': datetime.now().isoformat()
            })

        elif self.path.startswith('/check'):
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(self.path).query)
            ip = query.get('ip', [''])[0]

            if not ip:
                self.send_json({'error': 'Missing ip parameter'}, 400)
                return

            if ip in BLACKLIST:
                result = {
                    'ip': ip,
                    'action': 'BLOCK',
                    'level': 'NETWORK (iptables DROP)',
                    'reason': 'IP is blacklisted - blocked at TCP level'
                }
            elif ip in WHITELIST:
                result = {
                    'ip': ip,
                    'action': 'ALLOW',
                    'level': 'NETWORK + APPLICATION',
                    'reason': 'IP is whitelisted - full access through firewall'
                }
            else:
                result = {
                    'ip': ip,
                    'action': 'ALLOW (default)',
                    'level': 'APPLICATION',
                    'reason': 'IP not in blacklist - forwarded to Squid (L7) -> PEP for policy check'
                }

            self.send_json(result)

        elif self.path == '/' or self.path == '/index.html':
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>IPTables Firewall - TechCorp ZTA</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; margin: 0; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #ff7b72; border-bottom: 2px solid #ff7b72; padding-bottom: 10px; }}
        h2 {{ color: #79c0ff; margin-top: 30px; }}
        .box {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 16px 0; }}
        .blocked {{ color: #ff7b72; }}
        .allowed {{ color: #7ee787; }}
        .info {{ color: #79c0ff; }}
        pre {{ background: #0d1117; border: 1px solid #30363d; padding: 12px; overflow-x: auto; border-radius: 4px; }}
        code {{ color: #79c0ff; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }}
        th {{ color: #8b949e; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }}
        .stat {{ background: #21262d; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ color: #8b949e; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>IPTABLES FIREWALL</h1>
        <p>TechCorp Zero Trust Architecture - Network Level Security</p>

        <div class="box">
            <h2>How It Works - Defense in Depth</h2>
            <pre>
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐
│  External Host  │───▶│    IPTABLES     │───▶│      SQUID      │───▶│     PEP     │
│  172.28.1.x     │    │   (Layer 3/4)   │    │    (Layer 7)    │    │  (Policy)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────┘
                              │                       │
                       ┌──────┴──────┐         ┌──────┴──────┐
                       │ IP Blacklist│         │Domain Block │
                       │    DROP     │         │  URL Filter │
                       │ .200, .250  │         │  SQLi/XSS   │
                       └─────────────┘         └─────────────┘
            </pre>
        </div>

        <div class="box">
            <h2>Configuration</h2>
            <table>
                <tr><th>Setting</th><th>Value</th></tr>
                <tr><td>Upstream (Squid L7)</td><td><code>{UPSTREAM_IP}:{UPSTREAM_PORT}</code></td></tr>
                <tr><td>Listen Port</td><td><code>{LISTEN_PORT}</code></td></tr>
                <tr>
                    <td>Blacklist (Network DROP)</td>
                    <td class="blocked">{', '.join(BLACKLIST)}</td>
                </tr>
                <tr>
                    <td>Whitelist (Allowed)</td>
                    <td class="allowed">{', '.join(WHITELIST)}</td>
                </tr>
            </table>
        </div>

        <div class="box">
            <h2>API Endpoints</h2>
            <table>
                <tr><th>Endpoint</th><th>Description</th></tr>
                <tr><td><a href="/health">/health</a></td><td>Health check</td></tr>
                <tr><td><a href="/status">/status</a></td><td>Detailed status with statistics</td></tr>
                <tr><td><a href="/rules">/rules</a></td><td>Current iptables rules</td></tr>
                <tr><td><a href="/check?ip=172.28.1.200">/check?ip=X</a></td><td>Check if IP is blocked</td></tr>
            </table>
        </div>

        <div class="box">
            <h2>Security Model - Defense in Depth</h2>
            <p><span class="blocked">Layer 3 (iptables):</span> Blacklisted IPs are blocked at <strong>TCP level</strong>.
               They cannot even establish a connection - packets are DROPped before reaching any proxy.</p>
            <p><span class="info">Layer 7 (Squid):</span> Domain/URL filtering, SQLi/XSS pattern blocking,
               malicious domain blacklist. Preserves <code>X-Real-IP</code> header.</p>
            <p><span class="allowed">Policy (PEP/PDP):</span> Trust score calculation, role-based access control,
               dynamic policy evaluation based on user, device, and context.</p>
        </div>
    </div>
</body>
</html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())

        else:
            self.send_json({'error': 'Not found'}, 404)


# ============================================================================
# Main: Run both servers
# ============================================================================
def run_proxy_server():
    """Run the HTTP proxy server"""
    server = HTTPServer(('0.0.0.0', LISTEN_PORT), ProxyHandler)
    log(f"[PROXY] HTTP Proxy listening on port {LISTEN_PORT}")
    log(f"[PROXY] Forwarding to Squid (L7) at {UPSTREAM_IP}:{UPSTREAM_PORT}")
    server.serve_forever()


def run_status_server():
    """Run the status API server"""
    server = HTTPServer(('0.0.0.0', STATUS_PORT), StatusHandler)
    log(f"[STATUS] Status API listening on port {STATUS_PORT}")
    server.serve_forever()


if __name__ == '__main__':
    print("=" * 60)
    print(" IPTABLES FIREWALL - Starting Services")
    print("=" * 60)
    print(f" Blacklist: {BLACKLIST}")
    print(f" Whitelist: {WHITELIST}")
    print(f" Upstream (Squid L7): {UPSTREAM_IP}:{UPSTREAM_PORT}")
    print("=" * 60)

    # Start status server in background thread
    status_thread = threading.Thread(target=run_status_server, daemon=True)
    status_thread.start()

    # Run proxy server in main thread
    run_proxy_server()

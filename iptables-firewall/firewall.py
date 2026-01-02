#!/usr/bin/env python3
"""
IPTABLES FIREWALL SIMULATOR - Network Level Firewall
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime

PORT = 8888
BLACKLIST = ['172.28.1.200', '172.28.1.250', '172.28.1.60']
logs = []

def check_packet(src, dst):
    if src in BLACKLIST: return False, f"Source {src} blacklisted"
    if dst in BLACKLIST: return False, f"Dest {dst} blacklisted"
    if src.startswith('172.28.2.'): return True, "Internal allowed"
    if src.startswith('172.28.3.'): return True, "DMZ allowed"
    if src.startswith('172.28.4.') or src.startswith('172.28.5.'): return True, "Prod/Dev allowed"
    if src == '172.28.1.100': return True, "Whitelisted external"
    if src.startswith('172.28.1.'): return False, "External blocked"
    return True, "Default allow"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'active', 'blacklist': BLACKLIST, 'logs': logs[-20:]}).encode())
        elif self.path.startswith('/check'):
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query)
            src, dst = q.get('src', ['?'])[0], q.get('dst', ['?'])[0]
            ok, reason = check_packet(src, dst)
            action = "ACCEPT" if ok else "DROP"
            logs.append({'time': datetime.now().isoformat(), 'src': src, 'dst': dst, 'action': action})
            print(f"[IPTABLES-{action}] {src} -> {dst}: {reason}")
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'allowed': ok, 'action': action, 'reason': reason}).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>IPTABLES Firewall</h1><a href="/status">Status</a>')

if __name__ == '__main__':
    print('='*50)
    print('[IPTABLES] Network Level Firewall - Port', PORT)
    print('='*50)
    HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()

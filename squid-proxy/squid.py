#!/usr/bin/env python3
"""
SQUID PROXY SIMULATOR - Application Level Firewall
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import json
from datetime import datetime
import http.client

PORT = 3128
BLACKLIST_DOMAINS = ['external-blocked-server', 'blocked-server', 'malware-site.com']
BLACKLIST_IPS = ['172.28.1.200', '172.28.1.250', '172.28.1.60']

class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[SQUID] {datetime.now().isoformat()} {self.client_address[0]} {args[0]}")
    
    def is_blocked(self, host):
        for b in BLACKLIST_DOMAINS:
            if b in host.lower():
                return True
        return False
    
    def send_blocked(self, reason):
        self.send_response(403)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        html = f'''<!DOCTYPE html><html><head><title>Blocked</title></head>
<body style="font-family:Arial;background:#1a1a2e;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
<div style="text-align:center;background:rgba(231,76,60,0.2);border:2px solid #e74c3c;border-radius:20px;padding:40px;">
<h1 style="color:#e74c3c;">🚫 ACCESS DENIED</h1>
<p>Squid Proxy blocked: {reason}</p>
</div></body></html>'''
        self.wfile.write(html.encode())
    
    def do_GET(self):
        if self.path.startswith('http'):
            parsed = urlparse(self.path)
            host, port, path = parsed.hostname, parsed.port or 80, parsed.path or '/'
        else:
            host = self.headers.get('Host', '').split(':')[0]
            port, path = 80, self.path
        
        if self.is_blocked(host):
            print(f"[SQUID] BLOCKED: {host}")
            self.send_blocked(host)
            return
        
        try:
            print(f"[SQUID] FORWARD: {host}{path}")
            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request('GET', path)
            resp = conn.getresponse()
            self.send_response(resp.status)
            for h, v in resp.getheaders():
                if h.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(h, v)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as e:
            print(f"[SQUID] ERROR: {e}")
            self.send_response(502)
            self.end_headers()

if __name__ == '__main__':
    print('='*50)
    print('[SQUID] Application Level Firewall - Port', PORT)
    print('='*50)
    HTTPServer(('0.0.0.0', PORT), ProxyHandler).serve_forever()

#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime
import os

PORT = 80
SERVER_IP = os.environ.get('SERVER_IP', '172.28.1.50')

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[ALLOWED-SERVER] {datetime.now().isoformat()} {args[0]}")
    
    def do_GET(self):
        if self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'status': 'online',
                'server': 'Partner Fidato S.r.l.',
                'ip': SERVER_IP,
                'trust_level': 'whitelisted'
            }).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = f'''<!DOCTYPE html>
<html><head><title>Allowed Server</title></head>
<body style="font-family:Arial;background:#1a1a2e;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;">
<div style="text-align:center;background:rgba(39,174,96,0.2);border:2px solid #27ae60;border-radius:20px;padding:40px;">
<h1 style="color:#27ae60;">✅ Partner Fidato S.r.l.</h1>
<p>Server Whitelisted - IP: {SERVER_IP}</p>
<p style="color:#27ae60;">TRUSTED EXTERNAL SERVER</p>
</div></body></html>'''
            self.wfile.write(html.encode())

if __name__ == '__main__':
    print(f'[ALLOWED-SERVER] Starting on port {PORT} - IP: {SERVER_IP}')
    HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()

#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime
import os

PORT = 80
SERVER_IP = os.environ.get('SERVER_IP', '172.28.1.60')

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[BLOCKED-SERVER] ⚠️ {datetime.now().isoformat()} {args[0]}")
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        html = f'''<!DOCTYPE html>
<html><head><title>BLOCKED Server</title></head>
<body style="font-family:Arial;background:#2d1a1a;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;">
<div style="text-align:center;background:rgba(231,76,60,0.2);border:2px solid #e74c3c;border-radius:20px;padding:40px;">
<h1 style="font-size:60px;">💀</h1>
<h1 style="color:#e74c3c;">🚫 Malware Distribution Site</h1>
<p>Server Blacklisted - IP: {SERVER_IP}</p>
<p style="color:#e74c3c;border:1px solid #e74c3c;padding:10px;margin-top:20px;">
⚠️ Se vedi questa pagina, il firewall NON sta funzionando!
</p>
</div></body></html>'''
        self.wfile.write(html.encode())

if __name__ == '__main__':
    print(f'[BLOCKED-SERVER] ⚠️ Starting on port {PORT} - IP: {SERVER_IP}')
    HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()

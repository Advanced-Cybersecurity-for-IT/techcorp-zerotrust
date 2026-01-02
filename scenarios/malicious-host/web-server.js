/**
 * MALICIOUS HOST - ISOLATED
 * Questo host è completamente isolato dalla rete Zero Trust
 * Mostra SOLO una pagina di blocco
 */

const express = require('express');
const app = express();
const PORT = 8080;
const HOST_IP = process.env.HOST_IP || '172.28.1.250';

// Log all attempts
app.use((req, res, next) => {
    console.log(`[MALICIOUS-HOST] ⚠️ BLOCKED ACCESS ATTEMPT: ${req.method} ${req.path} from ${req.ip}`);
    next();
});

// ALL routes show blocked page
app.use('*', (req, res) => {
    res.status(403).send(`<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚫 ACCESS BLOCKED - Zero Trust</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #2d1a1a 50%, #1a1a2e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            overflow: hidden;
        }
        .container {
            background: rgba(0,0,0,0.5);
            backdrop-filter: blur(20px);
            border: 3px solid #e74c3c;
            border-radius: 30px;
            padding: 60px;
            max-width: 700px;
            text-align: center;
            box-shadow: 0 0 100px rgba(231, 76, 60, 0.3);
            animation: pulse-border 2s infinite;
        }
        @keyframes pulse-border {
            0%, 100% { border-color: #e74c3c; box-shadow: 0 0 100px rgba(231, 76, 60, 0.3); }
            50% { border-color: #c0392b; box-shadow: 0 0 150px rgba(231, 76, 60, 0.5); }
        }
        .warning-icon {
            font-size: 120px;
            margin-bottom: 30px;
            animation: shake 0.5s infinite;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        .warning-badge {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background: rgba(231, 76, 60, 0.3);
            border: 2px solid #e74c3c;
            padding: 12px 30px;
            border-radius: 50px;
            font-size: 18px;
            color: #e74c3c;
            margin-bottom: 30px;
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        h1 {
            color: #e74c3c;
            font-size: 48px;
            margin-bottom: 20px;
            text-shadow: 0 0 20px rgba(231, 76, 60, 0.5);
        }
        .subtitle {
            color: #888;
            font-size: 20px;
            margin-bottom: 40px;
        }
        .info-box {
            background: rgba(231, 76, 60, 0.1);
            border: 1px solid rgba(231, 76, 60, 0.3);
            border-radius: 15px;
            padding: 25px;
            margin: 30px 0;
        }
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            text-align: left;
        }
        .info-item {
            padding: 15px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
        }
        .info-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        .info-value {
            font-size: 18px;
            color: #e74c3c;
            font-family: monospace;
        }
        .reason-box {
            background: rgba(231, 76, 60, 0.2);
            border: 2px dashed #e74c3c;
            border-radius: 15px;
            padding: 25px;
            margin-top: 30px;
        }
        .reason-box h3 {
            color: #e74c3c;
            margin-bottom: 15px;
        }
        .reason-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
        }
        .reason-tag {
            background: rgba(231, 76, 60, 0.3);
            padding: 8px 20px;
            border-radius: 25px;
            font-size: 14px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid rgba(255,255,255,0.1);
            font-size: 14px;
            color: #666;
        }
        .shield {
            font-size: 40px;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-icon">🚫</div>
        <div class="warning-badge">
            ⚠️ SECURITY THREAT DETECTED
        </div>
        
        <h1>ACCESS BLOCKED</h1>
        <p class="subtitle">Zero Trust Architecture - Network Isolation Active</p>
        
        <div class="info-box">
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Host IP</div>
                    <div class="info-value">${HOST_IP}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Status</div>
                    <div class="info-value">BLACKLISTED</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Network Zone</div>
                    <div class="info-value">ISOLATED</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Trust Score</div>
                    <div class="info-value">0 / 100</div>
                </div>
            </div>
        </div>
        
        <div class="reason-box">
            <h3>🔒 Isolation Reasons</h3>
            <div class="reason-list">
                <span class="reason-tag">🦠 Malware Detected</span>
                <span class="reason-tag">🔓 Unauthorized Access</span>
                <span class="reason-tag">📡 Suspicious Traffic</span>
                <span class="reason-tag">🎯 Attack Patterns</span>
            </div>
        </div>
        
        <div class="footer">
            <div class="shield">🛡️</div>
            <p>This host has been completely isolated from the corporate network.</p>
            <p>No access to PEP, PDP, Keycloak, or any internal resources is permitted.</p>
            <p style="margin-top: 15px; color: #e74c3c;">
                Contact Security Team: security@techcorp.local
            </p>
        </div>
    </div>
</body>
</html>`);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log('============================================');
    console.log('[MALICIOUS-HOST] ⚠️ ISOLATED HOST ACTIVE');
    console.log(`   IP: ${HOST_IP}`);
    console.log(`   Port: ${PORT}`);
    console.log('   Status: NETWORK ISOLATED');
    console.log('   Access: ALL BLOCKED');
    console.log('============================================');
});

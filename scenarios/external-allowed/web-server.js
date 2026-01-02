const express = require('express');
const fetch = require('node-fetch');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 8080;
const HOST_TYPE = process.env.HOST_TYPE || 'development';
const SCENARIO_NAME = process.env.SCENARIO_NAME || 'DEV_NET';
const PEP_URL = process.env.PEP_URL || 'http://pep:8080';
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://keycloak:8080';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const SCENARIOS = {
    'DEV_NET': { name: 'Development', color: '#6366f1', gradient: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)', subnet: '172.28.5.x' },
    'PROD_NET': { name: 'Production', color: '#ef4444', gradient: 'linear-gradient(135deg, #ef4444 0%, #f97316 100%)', subnet: '172.28.4.x' },
    'EXTERNAL_ALLOWED': { name: 'External', color: '#10b981', gradient: 'linear-gradient(135deg, #10b981 0%, #14b8a6 100%)', subnet: '172.28.1.100' },
    'EXTERNAL_BLOCKED': { name: 'Blocked', color: '#ef4444', gradient: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)', subnet: '172.28.1.200' },
    'MALICIOUS_ATTACKER': { name: 'Threat', color: '#8b5cf6', gradient: 'linear-gradient(135deg, #8b5cf6 0%, #a855f7 100%)', subnet: '172.28.1.250' }
};

const scenario = SCENARIOS[SCENARIO_NAME] || SCENARIOS['DEV_NET'];

const BASE_CSS = `
    :root {
        --primary: #6366f1;
        --primary-dark: #4f46e5;
        --secondary: #8b5cf6;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --info: #06b6d4;
        --pink: #ec4899;
        --orange: #f97316;
        --gray-50: #f9fafb;
        --gray-100: #f3f4f6;
        --gray-200: #e5e7eb;
        --gray-300: #d1d5db;
        --gray-400: #9ca3af;
        --gray-500: #6b7280;
        --gray-600: #4b5563;
        --gray-700: #374151;
        --gray-800: #1f2937;
        --gray-900: #111827;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: var(--gray-50);
        color: var(--gray-800);
        line-height: 1.5;
        -webkit-font-smoothing: antialiased;
    }
`;

app.get('/', (req, res) => res.send(getDesktopPage()));

app.post('/navigate', (req, res) => {
    const url = (req.body.url || '').toLowerCase().trim();
    if (url.includes('techcorp') || url.includes('intranet') || url.includes('erp')) {
        res.redirect('/intranet');
    } else {
        res.redirect('/not-found?url=' + encodeURIComponent(url));
    }
});

app.get('/intranet', (req, res) => res.send(getIntranetPage(req.cookies.access_token, req.cookies.user_fullname, req.query)));

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const response = await fetch(`${KEYCLOAK_URL}/realms/techcorp/protocol/openid-connect/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'password',
                client_id: 'techcorp-pep',
                client_secret: 'techcorp-secret-2024',
                username,
                password
            })
        });
        const data = await response.json();
        if (data.access_token) {
            const payload = JSON.parse(Buffer.from(data.access_token.split('.')[1], 'base64').toString());
            res.cookie('access_token', data.access_token, { maxAge: 300000 });
            res.cookie('username', username, { maxAge: 300000 });
            res.cookie('user_fullname', `${payload.given_name || ''} ${payload.family_name || ''}`.trim() || username, { maxAge: 300000 });
            res.cookie('user_roles', JSON.stringify(payload.realm_access?.roles || []), { maxAge: 300000 });
            res.redirect('/dashboard');
        } else {
            res.redirect('/intranet?error=auth');
        }
    } catch (error) {
        res.redirect('/intranet?error=conn');
    }
});

app.get('/logout', (req, res) => {
    ['access_token', 'username', 'user_fullname', 'user_roles'].forEach(c => res.clearCookie(c));
    res.redirect('/');
});

app.get('/dashboard', async (req, res) => {
    if (!req.cookies.access_token) return res.redirect('/intranet');
    res.send(await getDashboardPage(req.cookies.access_token, req.cookies.username, req.cookies.user_fullname));
});

// External browser page
app.get('/browser', (req, res) => {
    if (!req.cookies.access_token) return res.redirect('/intranet');
    res.send(getExternalBrowserPage());
});

// Proxy to external servers - Simulates Squid Proxy behavior
app.get('/browse-external', async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) {
        return res.status(400).json({ error: 'URL parameter required' });
    }
    
    console.log(`[${SCENARIO_NAME}] External browse request to: ${targetUrl}`);
    
    // BLACKLIST - Sites blocked by Squid ACL
    const BLACKLIST = [
        'malware-download.net',
        'phishing-site.com', 
        'hacker-tools.org',
        'blocked-server',
        'virus-spread.net',
        '172.28.1.60',
        '172.28.1.200',
        '172.28.1.250'
    ];
    
    // Check if URL is blocked
    const isBlocked = BLACKLIST.some(domain => targetUrl.toLowerCase().includes(domain));
    
    if (isBlocked) {
        console.log(`[${SCENARIO_NAME}] 🚫 BLOCKED by Squid ACL: ${targetUrl}`);
        return res.send(getSquidBlockedPage(targetUrl));
    }
    
    // WHITELIST - Known partner sites (render custom pages)
    if (targetUrl.includes('logisticaitalia.com') || targetUrl.includes('external-allowed-server') || targetUrl.includes('172.28.1.50')) {
        return res.send(getPartnerSitePage());
    }
    
    if (targetUrl.includes('cloudservizi.it')) {
        return res.send(getCloudServiziPage());
    }
    
    // For other URLs, try to fetch or show not found
    try {
        const response = await fetch(targetUrl, { timeout: 5000 });
        const html = await response.text();
        res.send(html);
    } catch (error) {
        console.log(`[${SCENARIO_NAME}] Browse error: ${error.message}`);
        res.send(getNotFoundPage(targetUrl));
    }
});

function getSquidBlockedPage(url) {
    return `<!DOCTYPE html>
<html><head><title>Accesso Bloccato - Squid Proxy</title></head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(180deg,#1a1a2e 0%,#16213e 100%);color:#fff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;">
<div style="text-align:center;max-width:650px;padding:40px;">
<div style="background:#e74c3c;width:100px;height:100px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 30px;font-size:50px;box-shadow:0 10px 40px rgba(231,76,60,0.4);">🛡️</div>
<h1 style="color:#e74c3c;font-size:32px;margin:0 0 10px;">Accesso Bloccato</h1>
<p style="color:#888;font-size:18px;margin:0 0 30px;">Il sito richiesto è stato bloccato dal firewall aziendale</p>

<div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:25px;text-align:left;margin-bottom:30px;">
<table style="width:100%;border-collapse:collapse;color:#ccc;font-size:14px;">
<tr><td style="padding:8px 0;color:#888;">URL Richiesto:</td><td style="padding:8px 0;color:#e74c3c;word-break:break-all;">${url}</td></tr>
<tr><td style="padding:8px 0;color:#888;">Categoria:</td><td style="padding:8px 0;"><span style="background:#e74c3c;padding:3px 12px;border-radius:20px;font-size:12px;">Malware / Phishing</span></td></tr>
<tr><td style="padding:8px 0;color:#888;">Azione:</td><td style="padding:8px 0;">DENY</td></tr>
<tr><td style="padding:8px 0;color:#888;">Firewall:</td><td style="padding:8px 0;">Squid Proxy v5.7</td></tr>
<tr><td style="padding:8px 0;color:#888;">Timestamp:</td><td style="padding:8px 0;">${new Date().toLocaleString('it-IT')}</td></tr>
</table>
</div>

<div style="background:rgba(231,76,60,0.1);border:1px solid rgba(231,76,60,0.3);border-radius:8px;padding:15px;margin-bottom:30px;">
<p style="margin:0;color:#e74c3c;font-size:14px;">⚠️ Questo sito è nella blacklist aziendale. Se ritieni che sia un errore, contatta l'IT Security.</p>
</div>

<a href="/browser" style="display:inline-block;padding:14px 40px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;text-decoration:none;border-radius:10px;font-weight:600;box-shadow:0 4px 15px rgba(99,102,241,0.4);">← Torna al Browser</a>

<p style="color:#555;font-size:11px;margin-top:40px;">TechCorp Zero Trust Security • Application Level Firewall</p>
</div>
</body></html>`;
}

function getNotFoundPage(url) {
    return `<!DOCTYPE html>
<html><head><title>Sito non raggiungibile</title></head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5;color:#333;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;">
<div style="text-align:center;max-width:500px;padding:40px;">
<div style="font-size:80px;margin-bottom:20px;">🌐</div>
<h1 style="color:#333;font-size:24px;margin:0 0 10px;">Impossibile raggiungere il sito</h1>
<p style="color:#666;margin:0 0 20px;">${url}</p>
<p style="color:#888;font-size:14px;">Verifica che l'indirizzo sia corretto o che il server sia online.</p>
<a href="/browser" style="display:inline-block;margin-top:20px;padding:12px 30px;background:#6366f1;color:#fff;text-decoration:none;border-radius:8px;">← Torna al Browser</a>
</div>
</body></html>`;
}

function getPartnerSitePage() {
    return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logistica Italia S.r.l. - Partner Autorizzato</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .header {
            background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
            color: white;
            padding: 0;
        }
        .top-bar {
            background: rgba(0,0,0,0.2);
            padding: 8px 40px;
            font-size: 13px;
            display: flex;
            justify-content: space-between;
        }
        .top-bar a { color: #8ec8f8; text-decoration: none; margin-left: 20px; }
        .nav-main {
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .logo-icon {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #f39c12, #e74c3c);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        .logo-text h1 { font-size: 22px; font-weight: 700; }
        .logo-text span { font-size: 12px; opacity: 0.8; }
        .nav-links { display: flex; gap: 30px; }
        .nav-links a { color: white; text-decoration: none; font-weight: 500; padding: 10px 0; border-bottom: 2px solid transparent; }
        .nav-links a:hover { border-bottom-color: #f39c12; }
        .hero {
            background: linear-gradient(135deg, #2d5a87 0%, #1e3a5f 100%);
            color: white;
            padding: 80px 40px;
            text-align: center;
        }
        .hero h2 { font-size: 42px; margin-bottom: 20px; }
        .hero p { font-size: 18px; opacity: 0.9; max-width: 600px; margin: 0 auto 30px; }
        .hero-btn {
            display: inline-block;
            padding: 15px 40px;
            background: linear-gradient(135deg, #f39c12, #e67e22);
            color: white;
            text-decoration: none;
            border-radius: 30px;
            font-weight: 600;
            box-shadow: 0 4px 20px rgba(243,156,18,0.4);
        }
        .services {
            padding: 60px 40px;
            background: #f8f9fa;
        }
        .services h3 { text-align: center; font-size: 28px; color: #1e3a5f; margin-bottom: 40px; }
        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .service-card {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            text-align: center;
        }
        .service-icon { font-size: 40px; margin-bottom: 15px; }
        .service-card h4 { color: #1e3a5f; margin-bottom: 10px; }
        .service-card p { color: #666; font-size: 14px; }
        .partner-badge {
            background: linear-gradient(135deg, #27ae60, #2ecc71);
            color: white;
            padding: 20px 40px;
            text-align: center;
        }
        .partner-badge span { font-size: 14px; }
        .stats {
            padding: 50px 40px;
            background: white;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            max-width: 1000px;
            margin: 0 auto;
            text-align: center;
        }
        .stat-item h4 { font-size: 36px; color: #1e3a5f; margin-bottom: 5px; }
        .stat-item p { color: #888; font-size: 14px; }
        .footer {
            background: #1e3a5f;
            color: white;
            padding: 40px;
            text-align: center;
        }
        .footer p { opacity: 0.7; font-size: 13px; }
        .trust-badge {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: linear-gradient(135deg, #27ae60, #2ecc71);
            color: white;
            padding: 10px 20px;
            border-radius: 30px;
            font-size: 12px;
            box-shadow: 0 4px 15px rgba(39,174,96,0.4);
            display: flex;
            align-items: center;
            gap: 8px;
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="top-bar">
            <div>📞 +39 02 1234567 | ✉️ info@logisticaitalia.com</div>
            <div>
                <a href="#">Area Clienti</a>
                <a href="#">Tracking</a>
                <a href="#">Contatti</a>
            </div>
        </div>
        <nav class="nav-main">
            <div class="logo">
                <div class="logo-icon">🚚</div>
                <div class="logo-text">
                    <h1>Logistica Italia</h1>
                    <span>Spedizioni & Supply Chain</span>
                </div>
            </div>
            <div class="nav-links">
                <a href="#">Home</a>
                <a href="#">Servizi</a>
                <a href="#">Soluzioni B2B</a>
                <a href="#">Chi Siamo</a>
                <a href="#">News</a>
            </div>
        </nav>
    </header>
    
    <section class="hero">
        <h2>Soluzioni Logistiche per il Tuo Business</h2>
        <p>Partner ufficiale TechCorp per la gestione completa della supply chain. Spedizioni nazionali e internazionali con tracking in tempo reale.</p>
        <a href="#" class="hero-btn">Richiedi Preventivo</a>
    </section>
    
    <div class="partner-badge">
        <span>✓ Partner Certificato TechCorp • Accesso Autorizzato alla Rete Aziendale • Connessione Sicura SSL</span>
    </div>
    
    <section class="services">
        <h3>I Nostri Servizi</h3>
        <div class="services-grid">
            <div class="service-card">
                <div class="service-icon">📦</div>
                <h4>Spedizioni Express</h4>
                <p>Consegna in 24/48h in tutta Italia e Europa con tracking real-time</p>
            </div>
            <div class="service-card">
                <div class="service-icon">🏭</div>
                <h4>Logistica Magazzino</h4>
                <p>Gestione completa del magazzino con sistema WMS integrato</p>
            </div>
            <div class="service-card">
                <div class="service-icon">🌍</div>
                <h4>Import/Export</h4>
                <p>Sdoganamento e spedizioni internazionali via mare, terra e aria</p>
            </div>
            <div class="service-card">
                <div class="service-icon">📊</div>
                <h4>API Integration</h4>
                <p>Integrazione diretta con i sistemi ERP TechCorp</p>
            </div>
        </div>
    </section>
    
    <section class="stats">
        <div class="stats-grid">
            <div class="stat-item">
                <h4>15+</h4>
                <p>Anni di Esperienza</p>
            </div>
            <div class="stat-item">
                <h4>500+</h4>
                <p>Clienti Attivi</p>
            </div>
            <div class="stat-item">
                <h4>1M+</h4>
                <p>Spedizioni/Anno</p>
            </div>
            <div class="stat-item">
                <h4>99.2%</h4>
                <p>Consegne Puntuali</p>
            </div>
        </div>
    </section>
    
    <footer class="footer">
        <p>© 2024 Logistica Italia S.r.l. - P.IVA 12345678901 - Via dell'Industria 45, 20100 Milano</p>
        <p style="margin-top:10px;">Partner Ufficiale TechCorp | Certificazione ISO 9001:2015</p>
    </footer>
    
    <div class="trust-badge">
        <span>🔒</span> Connessione Verificata - Partner Autorizzato
    </div>
</body>
</html>`;
}

function getCloudServiziPage() {
    return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudServizi.it - Soluzioni Cloud Enterprise</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0a1a; color: white; }
        .header {
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .logo { display: flex; align-items: center; gap: 12px; font-size: 20px; font-weight: 700; }
        .logo span { color: #00d4ff; }
        .nav a { color: #888; text-decoration: none; margin-left: 30px; }
        .nav a:hover { color: white; }
        .hero {
            padding: 100px 40px;
            text-align: center;
            background: radial-gradient(ellipse at center, #1a1a3a 0%, #0a0a1a 70%);
        }
        .hero h1 { font-size: 48px; margin-bottom: 20px; }
        .hero h1 span { color: #00d4ff; }
        .hero p { color: #888; font-size: 18px; max-width: 600px; margin: 0 auto 40px; }
        .btn { display: inline-block; padding: 15px 40px; background: linear-gradient(135deg, #00d4ff, #0099cc); color: white; text-decoration: none; border-radius: 30px; font-weight: 600; }
        .features { padding: 80px 40px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; max-width: 1200px; margin: 0 auto; }
        .feature { background: rgba(255,255,255,0.05); padding: 30px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1); }
        .feature h3 { color: #00d4ff; margin-bottom: 15px; }
        .feature p { color: #888; font-size: 14px; }
        .partner-section { background: rgba(0,212,255,0.1); padding: 30px; text-align: center; border-top: 1px solid rgba(0,212,255,0.3); }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">☁️ Cloud<span>Servizi</span>.it</div>
        <nav class="nav">
            <a href="#">Prodotti</a>
            <a href="#">Soluzioni</a>
            <a href="#">Prezzi</a>
            <a href="#">Supporto</a>
        </nav>
    </header>
    <section class="hero">
        <h1>Il Cloud per la Tua <span>Azienda</span></h1>
        <p>Infrastruttura cloud sicura e scalabile. Partner certificato TechCorp per soluzioni enterprise.</p>
        <a href="#" class="btn">Inizia Gratis</a>
    </section>
    <section class="features">
        <div class="feature">
            <h3>☁️ Cloud Hosting</h3>
            <p>Server virtuali ad alte prestazioni con uptime garantito 99.99%</p>
        </div>
        <div class="feature">
            <h3>🔒 Sicurezza</h3>
            <p>Crittografia end-to-end e backup automatici giornalieri</p>
        </div>
        <div class="feature">
            <h3>📊 Analytics</h3>
            <p>Dashboard real-time per monitorare le tue risorse</p>
        </div>
    </section>
    <div class="partner-section">
        <p>🤝 Partner Certificato TechCorp • Integrazione API Nativa • Supporto 24/7</p>
    </div>
</body>
</html>`;
}

function getExternalBrowserPage() {
    return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechCorp Browser - Navigazione Sicura</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: #1a1a2e;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        /* Browser Chrome */
        .browser-chrome {
            background: linear-gradient(180deg, #2d2d3a 0%, #252532 100%);
            border-bottom: 1px solid #3d3d4a;
        }
        
        /* Tab Bar */
        .tab-bar {
            display: flex;
            align-items: center;
            padding: 8px 10px 0;
            gap: 5px;
        }
        .tab {
            background: #1a1a2e;
            padding: 10px 20px;
            border-radius: 8px 8px 0 0;
            font-size: 13px;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
            max-width: 200px;
        }
        .tab.active { background: #252532; }
        .tab-icon { font-size: 14px; }
        .tab-title { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .tab-close { opacity: 0.5; cursor: pointer; margin-left: auto; }
        .new-tab { background: transparent; color: #888; padding: 10px 15px; cursor: pointer; }
        
        /* Navigation Bar */
        .nav-bar {
            display: flex;
            align-items: center;
            padding: 10px 15px;
            gap: 10px;
            background: #252532;
        }
        .nav-btn {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: none;
            background: transparent;
            color: #888;
            font-size: 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .nav-btn:hover { background: rgba(255,255,255,0.1); color: #fff; }
        .nav-btn:disabled { opacity: 0.3; cursor: default; }
        
        .url-bar {
            flex: 1;
            display: flex;
            align-items: center;
            background: #1a1a2e;
            border-radius: 25px;
            padding: 8px 15px;
            border: 1px solid #3d3d4a;
        }
        .url-bar:focus-within { border-color: #6366f1; }
        .url-lock { color: #27ae60; margin-right: 10px; font-size: 14px; }
        .url-input {
            flex: 1;
            background: none;
            border: none;
            color: #fff;
            font-size: 14px;
            outline: none;
        }
        .url-input::placeholder { color: #666; }
        .url-go {
            background: #6366f1;
            border: none;
            color: white;
            padding: 6px 16px;
            border-radius: 15px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
        }
        .url-go:hover { background: #4f46e5; }
        
        /* Bookmarks Bar */
        .bookmarks-bar {
            display: flex;
            align-items: center;
            padding: 8px 15px;
            gap: 5px;
            background: #1e1e2e;
            border-bottom: 1px solid #3d3d4a;
        }
        .bookmark {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: rgba(255,255,255,0.05);
            border-radius: 5px;
            color: #ccc;
            font-size: 12px;
            cursor: pointer;
            text-decoration: none;
            border: 1px solid transparent;
        }
        .bookmark:hover { background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.1); }
        .bookmark-icon { font-size: 14px; }
        .bookmark.partner { border-left: 3px solid #27ae60; }
        .bookmark.blocked { border-left: 3px solid #e74c3c; opacity: 0.7; }
        
        /* Content Area */
        .browser-content {
            flex: 1;
            background: #fff;
            display: flex;
            flex-direction: column;
        }
        
        .start-page {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px;
            background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
        }
        
        .start-logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(99,102,241,0.3);
        }
        
        .start-title { color: #1a1a2e; font-size: 28px; margin-bottom: 8px; }
        .start-subtitle { color: #888; font-size: 14px; margin-bottom: 40px; }
        
        .quick-links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            max-width: 900px;
            width: 100%;
        }
        
        .quick-link {
            background: white;
            border-radius: 15px;
            padding: 25px;
            text-decoration: none;
            color: inherit;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            border: 2px solid transparent;
            transition: all 0.2s;
            cursor: pointer;
        }
        .quick-link:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0,0,0,0.12); }
        .quick-link.allowed { border-left: 4px solid #27ae60; }
        .quick-link.allowed:hover { border-color: #27ae60; }
        .quick-link.blocked { border-left: 4px solid #e74c3c; }
        .quick-link.blocked:hover { border-color: #e74c3c; }
        
        .quick-link-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin-bottom: 15px;
        }
        .quick-link.allowed .quick-link-icon { background: linear-gradient(135deg, #27ae60, #2ecc71); }
        .quick-link.blocked .quick-link-icon { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        
        .quick-link h3 { font-size: 16px; color: #1a1a2e; margin-bottom: 5px; }
        .quick-link p { font-size: 12px; color: #888; margin-bottom: 10px; }
        .quick-link .url { font-size: 11px; color: #6366f1; font-family: monospace; }
        
        .section-title {
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            width: 100%;
            max-width: 900px;
        }
        
        /* Result Frame */
        #result-frame {
            flex: 1;
            border: none;
            display: none;
        }
        
        .back-to-home {
            position: fixed;
            bottom: 20px;
            left: 20px;
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-size: 13px;
            display: none;
            z-index: 1000;
        }
        
        /* Status Bar */
        .status-bar {
            background: #252532;
            padding: 5px 15px;
            font-size: 11px;
            color: #888;
            display: flex;
            justify-content: space-between;
        }
        .status-secure { color: #27ae60; }
    </style>
</head>
<body>
    <div class="browser-chrome">
        <div class="tab-bar">
            <div class="tab active">
                <span class="tab-icon">🏠</span>
                <span class="tab-title" id="tab-title">Nuova scheda</span>
                <span class="tab-close">×</span>
            </div>
            <div class="new-tab">+</div>
        </div>
        <div class="nav-bar">
            <button class="nav-btn" onclick="goBack()" id="btn-back" disabled>←</button>
            <button class="nav-btn" onclick="goForward()" disabled>→</button>
            <button class="nav-btn" onclick="refresh()">↻</button>
            <button class="nav-btn" onclick="goHome()">🏠</button>
            <div class="url-bar">
                <span class="url-lock" id="url-lock">🔒</span>
                <input type="text" class="url-input" id="url-input" placeholder="Cerca o inserisci un indirizzo" 
                       onkeypress="if(event.key==='Enter')navigate()">
                <button class="url-go" onclick="navigate()">Vai</button>
            </div>
            <button class="nav-btn">⭐</button>
            <button class="nav-btn">⋮</button>
        </div>
        <div class="bookmarks-bar">
            <span style="color:#888;font-size:11px;margin-right:10px;">📁 Preferiti:</span>
            <a class="bookmark partner" onclick="navigateTo('https://www.logisticaitalia.com')">
                <span class="bookmark-icon">🚚</span> Logistica Italia
            </a>
            <a class="bookmark partner" onclick="navigateTo('https://www.cloudservizi.it')">
                <span class="bookmark-icon">☁️</span> CloudServizi
            </a>
            <a class="bookmark" onclick="navigateTo('https://erp.techcorp.local')">
                <span class="bookmark-icon">📊</span> ERP TechCorp
            </a>
            <a class="bookmark blocked" onclick="navigateTo('https://www.malware-download.net')">
                <span class="bookmark-icon">⚠️</span> Test Blocco
            </a>
        </div>
    </div>
    
    <div class="browser-content">
        <div class="start-page" id="start-page">
            <div class="start-logo">🌐</div>
            <h1 class="start-title">TechCorp Secure Browser</h1>
            <p class="start-subtitle">Navigazione protetta dalla Zero Trust Architecture</p>
            
            <p class="section-title">🤝 Partner & Fornitori Autorizzati</p>
            <div class="quick-links">
                <div class="quick-link allowed" onclick="navigateTo('https://www.logisticaitalia.com')">
                    <div class="quick-link-icon">🚚</div>
                    <h3>Logistica Italia S.r.l.</h3>
                    <p>Partner logistico per spedizioni e supply chain</p>
                    <span class="url">www.logisticaitalia.com</span>
                </div>
                <div class="quick-link allowed" onclick="navigateTo('https://www.cloudservizi.it')">
                    <div class="quick-link-icon">☁️</div>
                    <h3>CloudServizi.it</h3>
                    <p>Infrastruttura cloud e hosting enterprise</p>
                    <span class="url">www.cloudservizi.it</span>
                </div>
            </div>
            
            <p class="section-title" style="margin-top:40px;">🧪 Test Sicurezza (Siti Bloccati)</p>
            <div class="quick-links">
                <div class="quick-link blocked" onclick="navigateTo('https://www.malware-download.net')">
                    <div class="quick-link-icon">🦠</div>
                    <h3>Malware Download</h3>
                    <p>Sito di test per verifica blocco malware</p>
                    <span class="url">www.malware-download.net</span>
                </div>
                <div class="quick-link blocked" onclick="navigateTo('https://www.phishing-site.com/login')">
                    <div class="quick-link-icon">🎣</div>
                    <h3>Phishing Test</h3>
                    <p>Simulazione sito phishing</p>
                    <span class="url">www.phishing-site.com</span>
                </div>
            </div>
        </div>
        
        <iframe id="result-frame" sandbox="allow-same-origin allow-scripts"></iframe>
    </div>
    
    <a href="#" class="back-to-home" id="back-home" onclick="goHome();return false;">← Torna alla Home</a>
    
    <div class="status-bar">
        <span id="status-text">Pronto</span>
        <span class="status-secure">🔒 Connessione protetta • Squid Proxy attivo</span>
    </div>
    
    <script>
        let currentUrl = '';
        let history = [];
        let historyIndex = -1;
        
        function navigateTo(url) {
            document.getElementById('url-input').value = url;
            navigate();
        }
        
        function navigate() {
            const url = document.getElementById('url-input').value.trim();
            if (!url) return;
            
            currentUrl = url;
            document.getElementById('status-text').textContent = 'Caricamento: ' + url;
            document.getElementById('tab-title').textContent = url.replace('https://', '').replace('http://', '').split('/')[0];
            
            // Show loading
            document.getElementById('start-page').style.display = 'none';
            document.getElementById('result-frame').style.display = 'block';
            document.getElementById('back-home').style.display = 'block';
            document.getElementById('btn-back').disabled = false;
            
            // Fetch via proxy
            fetch('/browse-external?url=' + encodeURIComponent(url))
                .then(response => response.text())
                .then(html => {
                    document.getElementById('result-frame').srcdoc = html;
                    document.getElementById('status-text').textContent = 'Completato';
                    
                    // Update history
                    history.push(url);
                    historyIndex = history.length - 1;
                })
                .catch(error => {
                    document.getElementById('result-frame').srcdoc = '<div style="padding:50px;text-align:center;font-family:Arial;"><h1>Errore</h1><p>' + error.message + '</p></div>';
                    document.getElementById('status-text').textContent = 'Errore di connessione';
                });
        }
        
        function goHome() {
            document.getElementById('start-page').style.display = 'flex';
            document.getElementById('result-frame').style.display = 'none';
            document.getElementById('back-home').style.display = 'none';
            document.getElementById('url-input').value = '';
            document.getElementById('tab-title').textContent = 'Nuova scheda';
            document.getElementById('status-text').textContent = 'Pronto';
            document.getElementById('btn-back').disabled = true;
        }
        
        function goBack() {
            if (historyIndex > 0) {
                historyIndex--;
                document.getElementById('url-input').value = history[historyIndex];
                navigate();
            } else {
                goHome();
            }
        }
        
        function goForward() {
            if (historyIndex < history.length - 1) {
                historyIndex++;
                document.getElementById('url-input').value = history[historyIndex];
                navigate();
            }
        }
        
        function refresh() {
            if (currentUrl) navigate();
        }
    </script>
</body>
</html>`;
}

app.get('/api/*', async (req, res) => {
    const token = req.cookies.access_token;
    const HOST_IP = process.env.HOST_IP || '172.28.1.100';
    try {
        const headers = {
            'X-Forwarded-For': HOST_IP,
            'X-Real-IP': HOST_IP
        };
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        console.log(`[${SCENARIO_NAME}] API call to ${req.path} with IP headers: ${HOST_IP}`);
        const resp = await fetch(`${PEP_URL}${req.path}`, { headers });
        const data = await resp.json();
        res.status(resp.status).json(data);
    } catch (e) {
        console.error(`[${SCENARIO_NAME}] API error:`, e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get('/not-found', (req, res) => res.send(getNotFoundPage(req.query.url)));

function getDesktopPage() {
    return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechCorp Workstation</title>
    <style>
        ${BASE_CSS}
        body {
            background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4c1d95 100%);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .topbar {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 10px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .topbar-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            color: white;
            font-weight: 600;
            font-size: 15px;
        }
        .topbar-logo {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #f472b6 0%, #c084fc 100%);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 14px;
        }
        .topbar-right {
            display: flex;
            align-items: center;
            gap: 20px;
            color: rgba(255,255,255,0.8);
            font-size: 13px;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.2);
            padding: 6px 12px;
            border-radius: 20px;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .main-content {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 40px 20px;
        }
        .browser-frame {
            width: 100%;
            max-width: 950px;
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 80px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.1);
            overflow: hidden;
        }
        .browser-toolbar {
            background: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);
            padding: 14px 18px;
            display: flex;
            align-items: center;
            gap: 14px;
            border-bottom: 1px solid #e2e8f0;
        }
        .window-controls { display: flex; gap: 8px; }
        .window-btn { width: 14px; height: 14px; border-radius: 50%; }
        .btn-close { background: linear-gradient(135deg, #ff6b6b, #ee5253); }
        .btn-min { background: linear-gradient(135deg, #feca57, #ff9f43); }
        .btn-max { background: linear-gradient(135deg, #1dd1a1, #10ac84); }
        .url-input-wrapper {
            flex: 1;
            display: flex;
            align-items: center;
            background: white;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            padding: 10px 14px;
            transition: all 0.2s;
        }
        .url-input-wrapper:focus-within {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }
        .url-lock { color: #10b981; margin-right: 10px; font-size: 16px; }
        .url-input-wrapper input {
            flex: 1;
            border: none;
            outline: none;
            font-size: 14px;
            color: var(--gray-700);
        }
        .url-input-wrapper button {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .url-input-wrapper button:hover { 
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
        }
        .browser-body {
            padding: 60px 50px;
            text-align: center;
            background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
            min-height: 420px;
        }
        .corp-logo {
            width: 90px;
            height: 90px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%);
            border-radius: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 28px;
            color: white;
            font-size: 40px;
            font-weight: 700;
            box-shadow: 0 10px 40px rgba(99, 102, 241, 0.3);
        }
        .browser-body h1 { 
            font-size: 32px; 
            font-weight: 800; 
            background: linear-gradient(135deg, #1e1b4b 0%, #6366f1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px; 
        }
        .browser-body p { color: var(--gray-500); font-size: 16px; margin-bottom: 45px; }
        .quick-actions { display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; }
        .action-card {
            background: white;
            border: 2px solid var(--gray-200);
            border-radius: 16px;
            padding: 28px 36px;
            text-decoration: none;
            color: var(--gray-800);
            transition: all 0.3s;
            min-width: 180px;
            position: relative;
            overflow: hidden;
        }
        .action-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--secondary), var(--pink));
            opacity: 0;
            transition: opacity 0.3s;
        }
        .action-card:hover {
            border-color: var(--primary);
            box-shadow: 0 10px 40px rgba(99, 102, 241, 0.2);
            transform: translateY(-4px);
        }
        .action-card:hover::before { opacity: 1; }
        .action-icon {
            width: 56px;
            height: 56px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 16px;
            font-size: 24px;
        }
        .action-icon.purple { background: linear-gradient(135deg, #ede9fe, #ddd6fe); }
        .action-icon.blue { background: linear-gradient(135deg, #dbeafe, #bfdbfe); }
        .action-icon.green { background: linear-gradient(135deg, #d1fae5, #a7f3d0); }
        .action-card h3 { font-size: 16px; font-weight: 700; margin-bottom: 4px; color: var(--gray-800); }
        .action-card span { font-size: 13px; color: var(--gray-400); }
        .env-indicator {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: ${scenario.gradient};
            color: white;
            padding: 12px 20px;
            border-radius: 12px;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }
        .floating-shapes {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            pointer-events: none;
            overflow: hidden;
            z-index: 0;
        }
        .shape {
            position: absolute;
            border-radius: 50%;
            opacity: 0.1;
        }
        .shape-1 { width: 300px; height: 300px; background: #f472b6; top: -100px; right: -50px; }
        .shape-2 { width: 200px; height: 200px; background: #60a5fa; bottom: 10%; left: -50px; }
        .shape-3 { width: 150px; height: 150px; background: #a78bfa; top: 40%; right: 10%; }
        .main-content { position: relative; z-index: 1; }
    </style>
</head>
<body>
    <div class="floating-shapes">
        <div class="shape shape-1"></div>
        <div class="shape shape-2"></div>
        <div class="shape shape-3"></div>
    </div>
    <div class="topbar">
        <div class="topbar-brand">
            <div class="topbar-logo">T</div>
            TechCorp Systems
        </div>
        <div class="topbar-right">
            <div class="status-indicator">
                <span class="status-dot"></span>
                Zero Trust Active
            </div>
            <span id="clock"></span>
        </div>
    </div>
    <div class="main-content">
        <div class="browser-frame">
            <div class="browser-toolbar">
                <div class="window-controls">
                    <div class="window-btn btn-close"></div>
                    <div class="window-btn btn-min"></div>
                    <div class="window-btn btn-max"></div>
                </div>
                <form class="url-input-wrapper" method="POST" action="/navigate">
                    <span class="url-lock">🔒</span>
                    <input type="text" name="url" placeholder="Enter URL (e.g., erp.techcorp.local)" autofocus>
                    <button type="submit">Go</button>
                </form>
            </div>
            <div class="browser-body">
                <div class="corp-logo">T</div>
                <h1>TechCorp Enterprise</h1>
                <p>Secure access to corporate resources</p>
                <div class="quick-actions">
                    <a href="/intranet" class="action-card">
                        <div class="action-icon purple">📊</div>
                        <h3>ERP System</h3>
                        <span>erp.techcorp.local</span>
                    </a>
                    <a href="/intranet" class="action-card">
                        <div class="action-icon blue">📈</div>
                        <h3>Dashboard</h3>
                        <span>Analytics & Reports</span>
                    </a>
                    <a href="/browser" class="action-card">
                        <div class="action-icon green">🌐</div>
                        <h3>External Browser</h3>
                        <span>Partner & Fornitori</span>
                    </a>
                    <a href="/intranet" class="action-card">
                        <div class="action-icon orange">🛡️</div>
                        <h3>Security</h3>
                        <span>Trust Status</span>
                    </a>
                </div>
            </div>
        </div>
    </div>
    <div class="env-indicator">
        <span>⚡</span>
        ${scenario.name} Environment
    </div>
    <script>
        function updateClock() { document.getElementById('clock').textContent = new Date().toLocaleTimeString('it-IT', {hour:'2-digit', minute:'2-digit'}); }
        updateClock(); setInterval(updateClock, 1000);
    </script>
</body>
</html>`;
}

function getIntranetPage(token, fullname, query = {}) {
    const isLoggedIn = !!token;
    const hasError = query.error;
    
    if (isLoggedIn) {
        return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechCorp - Welcome</title>
    <style>
        ${BASE_CSS}
        body { 
            min-height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            background: linear-gradient(135deg, #fdf4ff 0%, #fae8ff 50%, #f3e8ff 100%);
        }
        .welcome-card { 
            background: white; 
            border-radius: 24px; 
            padding: 50px; 
            text-align: center; 
            box-shadow: 0 20px 60px rgba(139, 92, 246, 0.15);
            max-width: 420px; 
            width: 100%;
        }
        .avatar { 
            width: 100px; 
            height: 100px; 
            background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%); 
            border-radius: 50%; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            margin: 0 auto 28px; 
            color: white; 
            font-size: 40px; 
            font-weight: 600;
            box-shadow: 0 10px 30px rgba(99, 102, 241, 0.3);
        }
        .welcome-card h1 { 
            font-size: 26px; 
            background: linear-gradient(135deg, #1e1b4b, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px; 
        }
        .welcome-card p { color: var(--gray-500); margin-bottom: 36px; font-size: 15px; }
        .btn { 
            display: inline-flex; 
            align-items: center; 
            justify-content: center; 
            gap: 10px; 
            padding: 14px 28px; 
            border-radius: 12px; 
            font-size: 15px; 
            font-weight: 600; 
            text-decoration: none; 
            transition: all 0.3s; 
            border: none; 
            cursor: pointer;
            width: 100%;
        }
        .btn-primary { 
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); 
            color: white;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
        }
        .btn-primary:hover { 
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
        }
        .btn-secondary { 
            background: var(--gray-100); 
            color: var(--gray-600);
            margin-top: 12px;
        }
        .btn-secondary:hover { background: var(--gray-200); }
    </style>
</head>
<body>
    <div class="welcome-card">
        <div class="avatar">${(fullname || 'U')[0].toUpperCase()}</div>
        <h1>Welcome back, ${fullname}!</h1>
        <p>You are logged into TechCorp Enterprise System</p>
        <a href="/dashboard" class="btn btn-primary">
            📊 Open Dashboard
        </a>
        <a href="/logout" class="btn btn-secondary">Sign Out</a>
    </div>
</body>
</html>`;
    }

    return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechCorp - Sign In</title>
    <style>
        ${BASE_CSS}
        body { min-height: 100vh; display: flex; }
        .login-brand {
            flex: 1;
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #a855f7 100%);
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding: 60px;
            color: white;
            position: relative;
            overflow: hidden;
        }
        .login-brand::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -20%;
            width: 80%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 60%);
        }
        .brand-logo { 
            width: 70px; 
            height: 70px; 
            background: rgba(255,255,255,0.2); 
            border-radius: 18px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 32px; 
            font-weight: 700; 
            margin-bottom: 36px;
            backdrop-filter: blur(10px);
        }
        .login-brand h1 { font-size: 42px; font-weight: 800; margin-bottom: 16px; }
        .login-brand p { font-size: 17px; opacity: 0.9; line-height: 1.7; max-width: 400px; }
        .features { margin-top: 50px; display: flex; flex-direction: column; gap: 18px; }
        .feature { 
            display: flex; 
            align-items: center; 
            gap: 14px; 
            font-size: 15px; 
            opacity: 0.95;
            background: rgba(255,255,255,0.1);
            padding: 14px 18px;
            border-radius: 12px;
            backdrop-filter: blur(5px);
        }
        .feature-icon {
            width: 40px;
            height: 40px;
            background: rgba(255,255,255,0.2);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        .login-form-section { 
            flex: 1; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            padding: 40px; 
            background: white;
        }
        .login-form-wrapper { width: 100%; max-width: 400px; }
        .login-form-wrapper h2 { 
            font-size: 28px; 
            background: linear-gradient(135deg, #1e1b4b, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px; 
        }
        .login-form-wrapper > p { color: var(--gray-500); margin-bottom: 36px; font-size: 15px; }
        .form-group { margin-bottom: 22px; }
        .form-group label { display: block; font-size: 14px; font-weight: 600; color: var(--gray-700); margin-bottom: 8px; }
        .form-group input { 
            width: 100%; 
            padding: 14px 18px; 
            border: 2px solid var(--gray-200); 
            border-radius: 12px; 
            font-size: 15px; 
            transition: all 0.2s; 
        }
        .form-group input:focus { 
            outline: none; 
            border-color: var(--primary); 
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1); 
        }
        .btn-login { 
            width: 100%; 
            padding: 16px; 
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); 
            color: white; 
            border: none; 
            border-radius: 12px; 
            font-size: 16px; 
            font-weight: 700; 
            cursor: pointer; 
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
        }
        .btn-login:hover { 
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
        }
        .error-alert { 
            background: linear-gradient(135deg, #fef2f2, #fee2e2); 
            border: 2px solid #fecaca; 
            color: #dc2626; 
            padding: 14px 18px; 
            border-radius: 12px; 
            margin-bottom: 24px; 
            font-size: 14px; 
            display: flex; 
            align-items: center; 
            gap: 10px;
            font-weight: 500;
        }
        .security-note { 
            margin-top: 36px; 
            padding-top: 28px; 
            border-top: 2px solid var(--gray-100); 
            display: flex; 
            align-items: center; 
            gap: 14px; 
            color: var(--gray-500); 
            font-size: 13px; 
        }
        .security-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #dcfce7, #bbf7d0);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        @media (max-width: 900px) { .login-brand { display: none; } }
    </style>
</head>
<body>
    <div class="login-brand">
        <div class="brand-logo">T</div>
        <h1>TechCorp</h1>
        <p>Enterprise Resource Planning platform with Zero Trust security architecture. All access is verified, validated, and logged.</p>
        <div class="features">
            <div class="feature">
                <div class="feature-icon">🛡️</div>
                <span>Zero Trust Security Model</span>
            </div>
            <div class="feature">
                <div class="feature-icon">✓</div>
                <span>Continuous Authentication</span>
            </div>
            <div class="feature">
                <div class="feature-icon">📡</div>
                <span>Real-time Monitoring</span>
            </div>
        </div>
    </div>
    <div class="login-form-section">
        <div class="login-form-wrapper">
            <h2>Welcome back</h2>
            <p>Enter your credentials to access the system</p>
            ${hasError ? `<div class="error-alert">⚠️ Invalid credentials. Please try again.</div>` : ''}
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter your username" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit" class="btn-login">Sign In →</button>
            </form>
            <div class="security-note">
                <div class="security-icon">🔒</div>
                <span>Protected by Snort IDS, Splunk SIEM & Keycloak Identity Provider</span>
            </div>
        </div>
    </div>
</body>
</html>`;
}

async function getDashboardPage(token, username, fullname) {
    let stats = {employees:0, departments:0, customers:0, orders:0, projects:0};
    let employees=[], customers=[], orders=[], projects=[];
    let trustData = {trust_score:50, components:{}};
    
    const HOST_IP = process.env.HOST_IP || '172.28.1.100';
    const headers = {
        'Authorization': `Bearer ${token}`,
        'X-Forwarded-For': HOST_IP,
        'X-Real-IP': HOST_IP
    };
    console.log(`[${SCENARIO_NAME}] Dashboard loading with IP: ${HOST_IP}`);
    try { stats = (await (await fetch(`${PEP_URL}/api/db/stats`, {headers})).json()).data || stats; } catch(e){ console.error('Stats error:', e.message); }
    try { employees = (await (await fetch(`${PEP_URL}/api/db/employees`, {headers})).json()).data || []; } catch(e){}
    try { customers = (await (await fetch(`${PEP_URL}/api/db/customers`, {headers})).json()).data || []; } catch(e){}
    try { orders = (await (await fetch(`${PEP_URL}/api/db/orders`, {headers})).json()).data || []; } catch(e){}
    try { projects = (await (await fetch(`${PEP_URL}/api/db/projects`, {headers})).json()).data || []; } catch(e){}
    try { trustData = await (await fetch(`${PEP_URL}/api/trust-score`, {headers})).json(); } catch(e){ console.error('Trust score error:', e.message); }
    
    const ts = trustData.trust_score || 50;
    const tsColor = ts >= 70 ? '#10b981' : ts >= 40 ? '#f59e0b' : '#ef4444';
    const tsGradient = ts >= 70 ? 'linear-gradient(135deg, #10b981, #14b8a6)' : ts >= 40 ? 'linear-gradient(135deg, #f59e0b, #fbbf24)' : 'linear-gradient(135deg, #ef4444, #f97316)';
    const tsLabel = ts >= 70 ? 'Full Access' : ts >= 40 ? 'Limited' : 'Restricted';
    const totalRevenue = orders.reduce((s,o) => s + parseFloat(o.total_amount||0), 0);

    return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechCorp - Dashboard</title>
    <style>
        ${BASE_CSS}
        body { background: linear-gradient(135deg, #f5f3ff 0%, #ede9fe 50%, #fae8ff 100%); min-height: 100vh; }
        .header { 
            background: white; 
            border-bottom: 1px solid var(--gray-200); 
            padding: 0 24px; 
            position: sticky; 
            top: 0; 
            z-index: 100;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
        }
        .header-inner { max-width: 1400px; margin: 0 auto; height: 70px; display: flex; align-items: center; justify-content: space-between; }
        .header-brand { display: flex; align-items: center; gap: 14px; font-weight: 700; font-size: 18px; color: var(--gray-900); }
        .header-brand-icon { 
            width: 42px; 
            height: 42px; 
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); 
            border-radius: 12px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            color: white; 
            font-weight: 700;
            font-size: 18px;
        }
        .header-nav { display: flex; align-items: center; gap: 8px; }
        .nav-link { 
            padding: 10px 18px; 
            border-radius: 10px; 
            color: var(--gray-600); 
            text-decoration: none; 
            font-size: 14px; 
            font-weight: 600; 
            transition: all 0.2s; 
        }
        .nav-link:hover { background: var(--gray-100); color: var(--gray-900); }
        .nav-link.active { 
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); 
            color: white;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }
        .header-user { display: flex; align-items: center; gap: 16px; }
        .user-info { text-align: right; }
        .user-name { font-size: 14px; font-weight: 700; color: var(--gray-900); }
        .user-role { font-size: 12px; color: var(--gray-500); }
        .user-avatar { 
            width: 44px; 
            height: 44px; 
            background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%); 
            border-radius: 50%; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            color: white; 
            font-weight: 700;
            font-size: 16px;
        }
        .btn-logout { 
            padding: 10px 18px; 
            background: var(--gray-100); 
            border: 2px solid var(--gray-200); 
            border-radius: 10px; 
            color: var(--gray-600); 
            text-decoration: none; 
            font-size: 13px; 
            font-weight: 600;
            transition: all 0.2s; 
        }
        .btn-logout:hover { background: var(--gray-200); border-color: var(--gray-300); }
        .main { padding: 32px 24px; }
        .main-inner { max-width: 1400px; margin: 0 auto; }
        .page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 32px; flex-wrap: wrap; gap: 20px; }
        .page-title { 
            font-size: 28px; 
            font-weight: 800; 
            background: linear-gradient(135deg, #1e1b4b, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 6px; 
        }
        .page-subtitle { color: var(--gray-500); font-size: 15px; }
        .trust-card { 
            background: white; 
            border-radius: 16px; 
            padding: 20px 28px; 
            display: flex; 
            align-items: center; 
            gap: 18px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }
        .trust-score-ring { 
            width: 64px; 
            height: 64px; 
            border-radius: 50%; 
            background: conic-gradient(${tsColor} ${ts}%, #e5e7eb 0%); 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            padding: 5px; 
        }
        .trust-score-inner { 
            width: 100%; 
            height: 100%; 
            background: white; 
            border-radius: 50%; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 18px; 
            font-weight: 800; 
            color: ${tsColor}; 
        }
        .trust-info h3 { font-size: 15px; font-weight: 700; color: var(--gray-900); }
        .trust-info p { font-size: 12px; color: var(--gray-500); }
        .trust-badge { 
            padding: 6px 14px; 
            border-radius: 8px; 
            font-size: 12px; 
            font-weight: 700; 
            background: ${tsGradient}; 
            color: white;
        }
        .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; margin-bottom: 32px; }
        @media (max-width: 1200px) { .stats-grid { grid-template-columns: repeat(3, 1fr); } }
        @media (max-width: 700px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        .stat-card { 
            background: white; 
            border-radius: 16px; 
            padding: 24px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            transition: all 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 40px rgba(0,0,0,0.12);
        }
        .stat-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .stat-card-title { font-size: 13px; color: var(--gray-500); font-weight: 600; }
        .stat-card-icon { 
            width: 48px; 
            height: 48px; 
            border-radius: 14px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 22px;
        }
        .stat-card-icon.purple { background: linear-gradient(135deg, #ede9fe, #ddd6fe); }
        .stat-card-icon.green { background: linear-gradient(135deg, #d1fae5, #a7f3d0); }
        .stat-card-icon.blue { background: linear-gradient(135deg, #dbeafe, #bfdbfe); }
        .stat-card-icon.orange { background: linear-gradient(135deg, #ffedd5, #fed7aa); }
        .stat-card-icon.pink { background: linear-gradient(135deg, #fce7f3, #fbcfe8); }
        .stat-card-value { font-size: 32px; font-weight: 800; color: var(--gray-900); }
        .panels-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; }
        @media (max-width: 1000px) { .panels-grid { grid-template-columns: 1fr; } }
        .panel { 
            background: white; 
            border-radius: 16px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            overflow: hidden;
        }
        .panel-header { 
            padding: 20px 24px; 
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border-bottom: 1px solid var(--gray-200); 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        .panel-title { font-size: 16px; font-weight: 700; color: var(--gray-900); }
        .panel-count { 
            font-size: 12px; 
            color: white; 
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            padding: 5px 12px; 
            border-radius: 20px;
            font-weight: 600;
        }
        .panel-body { max-height: 340px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 14px 24px; text-align: left; border-bottom: 1px solid var(--gray-100); font-size: 13px; }
        th { 
            background: var(--gray-50); 
            font-weight: 700; 
            color: var(--gray-500); 
            text-transform: uppercase; 
            font-size: 11px; 
            letter-spacing: 0.5px; 
        }
        td { color: var(--gray-700); }
        tr:hover td { background: #faf5ff; }
        .badge { display: inline-block; padding: 5px 12px; border-radius: 6px; font-size: 11px; font-weight: 700; }
        .badge-success { background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #065f46; }
        .badge-warning { background: linear-gradient(135deg, #fef3c7, #fde68a); color: #92400e; }
        .badge-info { background: linear-gradient(135deg, #dbeafe, #bfdbfe); color: #1e40af; }
        .badge-danger { background: linear-gradient(135deg, #fee2e2, #fecaca); color: #dc2626; }
        .amount { font-weight: 700; color: var(--success); }
        .progress-bar { height: 8px; background: var(--gray-200); border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #6366f1, #a855f7); border-radius: 4px; }
        .env-badge { 
            position: fixed; 
            bottom: 24px; 
            left: 24px; 
            background: ${scenario.gradient}; 
            color: white; 
            padding: 10px 18px; 
            border-radius: 10px; 
            font-size: 13px; 
            font-weight: 700;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            gap: 8px;
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-inner">
            <div class="header-brand">
                <div class="header-brand-icon">T</div>
                <span>TechCorp ERP</span>
            </div>
            <nav class="header-nav">
                <a href="/dashboard" class="nav-link active">📊 Dashboard</a>
                <a href="/browser" class="nav-link">🌐 External Browser</a>
                <a href="/" class="nav-link">🏠 Home</a>
            </nav>
            <div class="header-user">
                <div class="user-info">
                    <div class="user-name">${fullname}</div>
                    <div class="user-role">Authenticated User</div>
                </div>
                <div class="user-avatar">${(fullname || 'U')[0].toUpperCase()}</div>
                <a href="/logout" class="btn-logout">Sign Out</a>
            </div>
        </div>
    </header>
    <main class="main">
        <div class="main-inner">
            <div class="page-header">
                <div>
                    <h1 class="page-title">Dashboard</h1>
                    <p class="page-subtitle">Overview of your enterprise data</p>
                </div>
                <div class="trust-card">
                    <div class="trust-score-ring">
                        <div class="trust-score-inner">${Math.round(ts)}</div>
                    </div>
                    <div class="trust-info">
                        <h3>🛡️ Trust Score</h3>
                        <p>Security Level</p>
                    </div>
                    <span class="trust-badge">${tsLabel}</span>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-card-header"><span class="stat-card-title">Employees</span><div class="stat-card-icon purple">👥</div></div><div class="stat-card-value">${stats.employees}</div></div>
                <div class="stat-card"><div class="stat-card-header"><span class="stat-card-title">Customers</span><div class="stat-card-icon green">🤝</div></div><div class="stat-card-value">${stats.customers}</div></div>
                <div class="stat-card"><div class="stat-card-header"><span class="stat-card-title">Orders</span><div class="stat-card-icon blue">📦</div></div><div class="stat-card-value">${stats.orders}</div></div>
                <div class="stat-card"><div class="stat-card-header"><span class="stat-card-title">Projects</span><div class="stat-card-icon orange">📁</div></div><div class="stat-card-value">${stats.projects}</div></div>
                <div class="stat-card"><div class="stat-card-header"><span class="stat-card-title">Revenue</span><div class="stat-card-icon pink">💰</div></div><div class="stat-card-value">€${(totalRevenue/1000).toFixed(0)}K</div></div>
            </div>
            <div class="panels-grid">
                <div class="panel">
                    <div class="panel-header"><span class="panel-title">📦 Recent Orders</span><span class="panel-count">${orders.length}</span></div>
                    <div class="panel-body">
                        <table><thead><tr><th>Order</th><th>Customer</th><th>Amount</th><th>Status</th></tr></thead>
                        <tbody>${orders.slice(0,8).map(o => `<tr><td><strong>${o.order_number}</strong></td><td>${o.customer_name || '-'}</td><td class="amount">€${parseFloat(o.total_amount||0).toLocaleString('it-IT')}</td><td><span class="badge ${o.status === 'delivered' ? 'badge-success' : o.status === 'pending' ? 'badge-warning' : 'badge-info'}">${o.status}</span></td></tr>`).join('')}</tbody></table>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-header"><span class="panel-title">🤝 Customers</span><span class="panel-count">${customers.length}</span></div>
                    <div class="panel-body">
                        <table><thead><tr><th>Company</th><th>Contact</th><th>Status</th></tr></thead>
                        <tbody>${customers.slice(0,8).map(c => `<tr><td><strong>${c.company_name}</strong></td><td>${c.contact_name || '-'}</td><td><span class="badge ${c.is_active ? 'badge-success' : 'badge-danger'}">${c.is_active ? 'Active' : 'Inactive'}</span></td></tr>`).join('')}</tbody></table>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-header"><span class="panel-title">👥 Employees</span><span class="panel-count">${employees.length}</span></div>
                    <div class="panel-body">
                        <table><thead><tr><th>Name</th><th>Department</th><th>Position</th></tr></thead>
                        <tbody>${employees.slice(0,8).map(e => `<tr><td><strong>${e.first_name} ${e.last_name}</strong></td><td>${e.department}</td><td>${e.position}</td></tr>`).join('')}</tbody></table>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-header"><span class="panel-title">📁 Projects</span><span class="panel-count">${projects.length}</span></div>
                    <div class="panel-body">
                        <table><thead><tr><th>Project</th><th>Budget</th><th>Progress</th></tr></thead>
                        <tbody>${projects.slice(0,8).map(p => `<tr><td><strong>${p.name}</strong></td><td>€${parseFloat(p.budget||0).toLocaleString('it-IT')}</td><td style="width:130px"><div class="progress-bar"><div class="progress-fill" style="width:${p.completion_percentage||0}%"></div></div><small style="color:var(--gray-500);font-size:11px;font-weight:600">${p.completion_percentage||0}%</small></td></tr>`).join('')}</tbody></table>
                    </div>
                </div>
            </div>
        </div>
    </main>
    <div class="env-badge">⚡ ${scenario.name}</div>
</body>
</html>`;
}

function getNotFoundPage(url) {
    return `<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Not Found</title>
    <style>
        ${BASE_CSS}
        body { 
            min-height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center;
            background: linear-gradient(135deg, #fdf4ff 0%, #fae8ff 50%, #f3e8ff 100%);
        }
        .error-container { text-align: center; max-width: 420px; }
        .error-icon {
            width: 120px;
            height: 120px;
            background: linear-gradient(135deg, #fee2e2, #fecaca);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            font-size: 48px;
        }
        .error-code { 
            font-size: 72px; 
            font-weight: 800; 
            background: linear-gradient(135deg, #ef4444, #f97316);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 12px; 
        }
        .error-title { font-size: 24px; color: var(--gray-800); margin-bottom: 8px; font-weight: 700; }
        .error-message { color: var(--gray-500); margin-bottom: 28px; }
        .btn-back { 
            display: inline-block; 
            padding: 14px 28px; 
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); 
            color: white; 
            text-decoration: none; 
            border-radius: 12px; 
            font-weight: 700;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
            transition: all 0.3s; 
        }
        .btn-back:hover { 
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">🔍</div>
        <div class="error-code">404</div>
        <h1 class="error-title">Page Not Found</h1>
        <p class="error-message">The requested URL "${url || 'unknown'}" could not be found.</p>
        <a href="/" class="btn-back">← Return Home</a>
    </div>
</body>
</html>`;
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[${SCENARIO_NAME}] Server running on port ${PORT}`);
});

/**
 * ============================================================================
 * PEP - Policy Enforcement Point
 * Zero Trust Architecture - TechCorp
 * ============================================================================
 * Il PEP è il gateway che:
 * 1. Riceve le richieste dagli utenti
 * 2. Consulta il PDP per la decisione
 * 3. Se approvato, accede al DBMS come client
 * 4. Restituisce i dati all'utente
 * ============================================================================
 */

const express = require('express');
const { Pool } = require('pg');
const fetch = require('node-fetch');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

const app = express();
const PORT = process.env.PORT || 8080;

// Keycloak configuration
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://keycloak:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'techcorp';

// ============================================================================
// CONFIGURATION
// ============================================================================
const PDP_URL = process.env.PDP_URL || 'http://pdp:5000';
const SNORT_IDS_URL = process.env.SNORT_IDS_URL || 'http://snort-ids:9090';
const DB_CONFIG = {
    host: process.env.DB_HOST || 'postgres-db',
    port: parseInt(process.env.DB_PORT) || 5432,
    user: process.env.DB_USER || 'techcorp_user',
    password: process.env.DB_PASSWORD || 'TechCorp2024!',
    database: process.env.DB_NAME || 'techcorp_db'
};

// Database connection pool
const pool = new Pool(DB_CONFIG);

app.use(express.json());
app.use(morgan('combined'));

// ============================================================================
// JWKS CLIENT: Fetches public keys from Keycloak
// ============================================================================
const jwksClient = jwksRsa({
    jwksUri: `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs`,
    cache: true,
    cacheMaxEntries: 5,
    cacheMaxAge: 600000, // 10 minutes
    rateLimit: true,
    jwksRequestsPerMinute: 10
});

// Helper function to get signing key
function getSigningKey(header, callback) {
    jwksClient.getSigningKey(header.kid, (err, key) => {
        if (err) {
            console.error('[PEP] Error fetching signing key:', err.message);
            callback(err, null);
        } else {
            const signingKey = key.getPublicKey();
            callback(null, signingKey);
        }
    });
}

// Allowed issuers (internal Docker hostname and external localhost access)
const ALLOWED_ISSUERS = [
    `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`,
    `http://localhost:8180/realms/${KEYCLOAK_REALM}`,
    `http://127.0.0.1:8180/realms/${KEYCLOAK_REALM}`
];

// Promisified JWT verification
function verifyToken(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getSigningKey, {
            algorithms: ['RS256'],
            issuer: ALLOWED_ISSUERS
        }, (err, decoded) => {
            if (err) {
                reject(err);
            } else {
                resolve(decoded);
            }
        });
    });
}

// ============================================================================
// MIDDLEWARE: Extract and VERIFY user info from token
// ============================================================================
const extractUserInfo = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    let userInfo = {
        username: 'anonymous',
        roles: [],
        email: null,
        verified: false
    };

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
            // Cryptographically verify the token against Keycloak's public key
            const decoded = await verifyToken(token);

            userInfo.username = decoded.preferred_username || decoded.sub || 'unknown';
            userInfo.roles = decoded.realm_access?.roles || [];
            userInfo.email = decoded.email;
            userInfo.name = `${decoded.given_name || ''} ${decoded.family_name || ''}`.trim();
            userInfo.verified = true;

            console.log(`[PEP] Token VERIFIED for user: ${userInfo.username}, roles: ${userInfo.roles.join(', ')}`);
        } catch (e) {
            console.error(`[PEP] Token verification FAILED: ${e.message}`);
            // Token provided but invalid - reject the request
            return res.status(401).json({
                error: 'Invalid or expired token',
                details: e.message,
                hint: 'Please obtain a valid token from Keycloak'
            });
        }
    }

    req.userInfo = userInfo;
    next();
};

app.use(extractUserInfo);

// ============================================================================
// SNORT IDS CLIENT: Analisi del traffico per IDS
// ============================================================================
async function analyzeWithSnort(req) {
    try {
        const packetData = {
            source_ip: getClientIP(req),
            dest_ip: '172.28.2.40',  // Database IP
            source_port: 0,
            dest_port: 5432,
            protocol: 'HTTP',
            payload: JSON.stringify(req.body || {}),
            headers: req.headers,
            method: req.method,
            uri: req.originalUrl,
            user_agent: req.headers['user-agent'] || ''
        };
        
        const response = await fetch(`${SNORT_IDS_URL}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(packetData),
            timeout: 3000
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.blocked) {
                console.log(`[PEP] SNORT IDS BLOCKED request from ${packetData.source_ip}: ${result.alerts_count} alerts`);
            }
            return result;
        }
        
        return { blocked: false, alerts: [] };
    } catch (error) {
        console.error('[PEP] Snort IDS error:', error.message);
        // Fail-open for IDS (don't block if IDS unavailable)
        return { blocked: false, alerts: [], error: error.message };
    }
}

// ============================================================================
// PDP CLIENT: Consulta il PDP per le decisioni
// ============================================================================
async function consultPDP(username, roles, sourceIP, resourceType, action) {
    try {
        // Determine network type based on IP
        let networkType = 'unknown';
        if (sourceIP.startsWith('172.28.4.')) networkType = 'production';
        else if (sourceIP.startsWith('172.28.5.')) networkType = 'development';
        else if (sourceIP.startsWith('172.28.2.')) networkType = 'internal';
        else if (sourceIP.startsWith('172.28.3.')) networkType = 'dmz';
        else if (sourceIP.startsWith('172.28.1.')) networkType = 'external';
        
        console.log(`[PEP] Consulting PDP - User: ${username}, IP: ${sourceIP}, Network: ${networkType}`);
        
        const requestData = {
            subject: {
                username,
                roles,
                token: 'present'
            },
            device: {
                ip: sourceIP,
                hostname: 'unknown',
                network: networkType
            },
            resource: {
                type: resourceType,
                action: action,
                path: `/${resourceType}`
            },
            context: {
                timestamp: new Date().toISOString(),
                user_agent: 'PEP-Client'
            }
        };
        
        const response = await fetch(`${PDP_URL}/evaluate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData),
            timeout: 5000
        });
        
        if (response.ok) {
            return await response.json();
        }
        
        return { decision: 'deny', reason: 'PDP unavailable' };
    } catch (error) {
        console.error('[PEP] PDP consultation error:', error.message);
        // Fail-safe: deny if PDP is unavailable
        return { decision: 'deny', reason: 'PDP error: ' + error.message };
    }
}

// ============================================================================
// DBMS CLIENT: Accesso al database
// ============================================================================
async function queryDatabase(query, params = []) {
    const client = await pool.connect();
    try {
        const result = await client.query(query, params);
        return result.rows;
    } finally {
        client.release();
    }
}

// ============================================================================
// MIDDLEWARE: IDS Analysis (Snort)
// ============================================================================
const idsAnalysis = async (req, res, next) => {
    // Skip health checks
    if (req.path === '/health') {
        return next();
    }
    
    try {
        const idsResult = await analyzeWithSnort(req);
        req.idsResult = idsResult;
        
        // Block if IDS detected malicious traffic
        if (idsResult.blocked) {
            console.log(`[PEP] Request BLOCKED by IDS - ${idsResult.alerts_count} alerts`);
            return res.status(403).json({
                error: 'Request blocked by Intrusion Detection System',
                alerts: idsResult.alerts.map(a => ({
                    rule: a.rule_name,
                    severity: a.severity,
                    category: a.category
                })),
                blocked_by: 'Snort-IDS'
            });
        }
    } catch (e) {
        // Continue even if IDS fails
        console.error('[PEP] IDS middleware error:', e.message);
    }
    
    next();
};

// Apply IDS middleware to all API routes
app.use('/api', idsAnalysis);

// ============================================================================
// API ENDPOINTS
// ============================================================================

// Helper function to get real client IP
function getClientIP(req) {
    // Priority: X-Real-IP > X-Forwarded-For > req.ip
    const realIP = req.headers['x-real-ip'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const directIP = req.ip || req.connection?.remoteAddress;
    
    let clientIP = realIP || (forwardedFor ? forwardedFor.split(',')[0].trim() : null) || directIP || 'unknown';
    
    // Remove IPv6 prefix if present
    if (clientIP.startsWith('::ffff:')) {
        clientIP = clientIP.substring(7);
    }
    
    console.log(`[PEP] IP Detection - X-Real-IP: ${realIP}, X-Forwarded-For: ${forwardedFor}, Direct: ${directIP} => Using: ${clientIP}`);
    
    return clientIP;
}

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', service: 'PEP', timestamp: new Date().toISOString() });
});

// Get trust score
app.get('/api/trust-score', async (req, res) => {
    try {
        const sourceIP = getClientIP(req);
        console.log(`[PEP] Trust score request for ${req.userInfo.username} from IP: ${sourceIP}`);
        
        const response = await fetch(`${PDP_URL}/trust-score`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: req.userInfo.username,
                source_ip: sourceIP,
                roles: req.userInfo.roles
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            res.json(data);
        } else {
            res.json({ trust_score: 50, components: {} });
        }
    } catch (e) {
        res.json({ trust_score: 50, error: e.message });
    }
});

// ============================================================================
// RESOURCE ENDPOINTS (protetti da PDP)
// ============================================================================

// EMPLOYEES
app.get('/api/db/employees', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'employees', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied', reason: decision.reason, trust_score: decision.trust_score });
    }
    
    try {
        const data = await queryDatabase('SELECT * FROM enterprise.employees WHERE is_active = true ORDER BY last_name');
        res.json({ success: true, count: data.length, data, trust_score: decision.trust_score });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// CUSTOMERS
app.get('/api/db/customers', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'customers', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied', reason: decision.reason, trust_score: decision.trust_score });
    }
    
    try {
        const data = await queryDatabase('SELECT * FROM enterprise.customers WHERE is_active = true ORDER BY company_name');
        res.json({ success: true, count: data.length, data, trust_score: decision.trust_score });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ORDERS
app.get('/api/db/orders', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'orders', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied', reason: decision.reason, trust_score: decision.trust_score });
    }
    
    try {
        const data = await queryDatabase(`
            SELECT o.*, c.company_name 
            FROM enterprise.orders o 
            LEFT JOIN enterprise.customers c ON o.customer_id = c.id 
            ORDER BY o.order_date DESC
        `);
        res.json({ success: true, count: data.length, data, trust_score: decision.trust_score });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// PROJECTS
app.get('/api/db/projects', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'projects', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied', reason: decision.reason, trust_score: decision.trust_score });
    }
    
    try {
        const data = await queryDatabase('SELECT * FROM enterprise.projects ORDER BY start_date DESC');
        res.json({ success: true, count: data.length, data, trust_score: decision.trust_score });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// DEPARTMENTS
app.get('/api/db/departments', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'stats', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied', reason: decision.reason });
    }
    
    try {
        const data = await queryDatabase('SELECT * FROM enterprise.departments ORDER BY name');
        res.json({ success: true, count: data.length, data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// PRODUCTS
app.get('/api/db/products', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'stats', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied', reason: decision.reason });
    }
    
    try {
        const data = await queryDatabase('SELECT * FROM enterprise.products WHERE is_active = true ORDER BY name');
        res.json({ success: true, count: data.length, data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// STATS
app.get('/api/db/stats', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'stats', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied', reason: decision.reason, trust_score: decision.trust_score });
    }
    
    try {
        const stats = {};
        stats.employees = parseInt((await queryDatabase('SELECT COUNT(*) FROM enterprise.employees WHERE is_active = true'))[0].count);
        stats.departments = parseInt((await queryDatabase('SELECT COUNT(*) FROM enterprise.departments'))[0].count);
        stats.customers = parseInt((await queryDatabase('SELECT COUNT(*) FROM enterprise.customers WHERE is_active = true'))[0].count);
        stats.orders = parseInt((await queryDatabase('SELECT COUNT(*) FROM enterprise.orders'))[0].count);
        stats.projects = parseInt((await queryDatabase('SELECT COUNT(*) FROM enterprise.projects'))[0].count);
        stats.products = parseInt((await queryDatabase('SELECT COUNT(*) FROM enterprise.products WHERE is_active = true'))[0].count);
        
        res.json({ success: true, data: stats, trust_score: decision.trust_score });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// AUDIT LOG (solo admin)
app.get('/api/db/audit', async (req, res) => {
    const sourceIP = getClientIP(req);
    const decision = await consultPDP(req.userInfo.username, req.userInfo.roles, sourceIP, 'audit', 'read');
    
    if (decision.decision !== 'allow') {
        return res.status(403).json({ error: 'Access denied - Admin only', reason: decision.reason });
    }
    
    try {
        const data = await queryDatabase('SELECT * FROM enterprise.audit_log ORDER BY timestamp DESC LIMIT 100');
        res.json({ success: true, count: data.length, data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ============================================================================
// START SERVER
// ============================================================================
app.listen(PORT, '0.0.0.0', () => {
    console.log('============================================');
    console.log('PEP - Policy Enforcement Point');
    console.log('Zero Trust Architecture - TechCorp');
    console.log('============================================');
    console.log(`Port: ${PORT}`);
    console.log(`PDP: ${PDP_URL}`);
    console.log(`Database: ${DB_CONFIG.host}:${DB_CONFIG.port}`);
    console.log('============================================');
});

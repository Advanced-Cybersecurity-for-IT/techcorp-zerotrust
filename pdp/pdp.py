"""
============================================================================
PDP - Policy Decision Point
Zero Trust Architecture - TechCorp
============================================================================
Il PDP valuta le richieste di accesso basandosi su:
1. Policy statiche (ACL, ruoli)
2. Storico dal SIEM (Splunk) per calcolo Trust Score dinamico
3. Contesto della richiesta (IP, tempo, risorsa)
============================================================================
"""

import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import requests

# Configurazione logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [PDP] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================================
# CONFIGURAZIONE
# ============================================================================
SPLUNK_HOST = os.environ.get('SPLUNK_HOST', 'splunk')
SPLUNK_PORT = os.environ.get('SPLUNK_PORT', '8089')
SPLUNK_USER = os.environ.get('SPLUNK_USER', 'admin')
SPLUNK_PASSWORD = os.environ.get('SPLUNK_PASSWORD', 'TechCorp2024!')
SPLUNK_HEC_TOKEN = os.environ.get('SPLUNK_HEC_TOKEN', 'techcorp-hec-token-2024')

# ============================================================================
# DEFINIZIONE POLICY
# ============================================================================
POLICIES = {
    "ip_whitelist": [
        "172.28.1.100",      # Host esterno autorizzato
        "172.28.1.50",       # Server esterno autorizzato
        "172.28.4.0/24",     # Rete di produzione (Production)
        "172.28.5.0/24",     # Rete di sviluppo (Development)
        "172.28.2.0/24",     # Rete interna
        "172.28.3.0/24",     # Rete DMZ
    ],
    "ip_blacklist": [
        "172.28.1.200",      # Host esterno bloccato
        "172.28.1.250",      # Host malevolo
        "172.28.1.60",       # Server bloccato
    ],
    "roles_permissions": {
        "ceo": {"read": True, "write": True, "delete": True, "admin": True},
        "cto": {"read": True, "write": True, "delete": True, "admin": True},
        "hr_manager": {"read": True, "write": True, "delete": False, "admin": False},
        "sales_manager": {"read": True, "write": True, "delete": False, "admin": False},
        "developer": {"read": True, "write": False, "delete": False, "admin": False},
        "analyst": {"read": True, "write": False, "delete": False, "admin": False},
    },
    "resource_access": {
        "employees": {"min_trust": 50, "roles": ["ceo", "cto", "hr_manager", "developer", "analyst"]},
        "customers": {"min_trust": 60, "roles": ["ceo", "cto", "sales_manager", "analyst"]},
        "orders": {"min_trust": 60, "roles": ["ceo", "cto", "sales_manager", "analyst"]},
        "projects": {"min_trust": 50, "roles": ["ceo", "cto", "developer", "analyst"]},
        "audit": {"min_trust": 80, "roles": ["ceo", "cto"]},
        "stats": {"min_trust": 40, "roles": ["ceo", "cto", "hr_manager", "sales_manager", "developer", "analyst"]},
    },
    "trust_thresholds": {
        "full_access": 80,
        "standard_access": 60,
        "limited_access": 40,
        "denied": 0
    },
    "time_restrictions": {
        "business_hours": {"start": 8, "end": 20},
        "weekend_allowed_roles": ["ceo", "cto"]
    }
}

# ============================================================================
# CLIENT SIEM - Interroga Splunk per lo storico degli eventi
# ============================================================================
class SIEMClient:
    def __init__(self):
        self.base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
        self.session = requests.Session()
        self.session.verify = False  # In produzione usare certificati validi
        self.session.auth = (SPLUNK_USER, SPLUNK_PASSWORD)
    
    def query_user_history(self, username, hours=24):
        """Interroga il SIEM per ottenere lo storico dell'utente"""
        try:
            search_query = f'search index=zerotrust username="{username}" earliest=-{hours}h'
            response = self.session.post(
                f"{self.base_url}/services/search/jobs",
                data={
                    'search': search_query,
                    'output_mode': 'json',
                    'exec_mode': 'oneshot'
                },
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.warning(f"SIEM query failed: {e}")
            return None
    
    def get_security_events(self, source_ip, hours=1):
        """Ottiene eventi di sicurezza per un IP"""
        try:
            search_query = f'search index=zerotrust source_ip="{source_ip}" (alert OR blocked OR denied) earliest=-{hours}h | stats count'
            response = self.session.post(
                f"{self.base_url}/services/search/jobs",
                data={
                    'search': search_query,
                    'output_mode': 'json',
                    'exec_mode': 'oneshot'
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return int(data.get('results', [{}])[0].get('count', 0))
            return 0
        except Exception as e:
            logger.warning(f"SIEM security events query failed: {e}")
            return 0
    
    def log_decision(self, decision_data):
        """Invia la decisione al SIEM per il logging"""
        try:
            hec_url = f"https://{SPLUNK_HOST}:8088/services/collector/event"
            headers = {
                'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',
                'Content-Type': 'application/json'
            }
            payload = {
                'event': decision_data,
                'index': 'zerotrust',
                'sourcetype': 'pdp_decision'
            }
            requests.post(hec_url, headers=headers, json=payload, verify=False, timeout=5)
        except Exception as e:
            logger.warning(f"Failed to log decision to SIEM: {e}")

siem_client = SIEMClient()

# ============================================================================
# CALCOLO TRUST SCORE
# ============================================================================
def calculate_trust_score(username, source_ip, user_roles, context):
    """
    Calcola il Trust Score dinamico basato su:
    - Base trust dal ruolo utente (30%)
    - History dal SIEM (25%)
    - Anomaly score (25%)
    - Context score (20%)
    """
    components = {}
    
    # 1. BASE TRUST (30%) - Dal ruolo utente
    role_trust = {
        "ceo": 100, "cto": 95, "hr_manager": 85, "sales_manager": 80,
        "developer": 75, "analyst": 70, "default": 50
    }
    max_role_trust = max([role_trust.get(r, 50) for r in user_roles], default=50)
    components['base_trust'] = max_role_trust
    
    # 2. HISTORY SCORE (25%) - Dal SIEM
    history = siem_client.query_user_history(username)
    if history:
        # Analizza history per calcolare score
        failed_attempts = history.get('failed_count', 0)
        successful_attempts = history.get('success_count', 1)
        history_score = min(100, (successful_attempts / (successful_attempts + failed_attempts)) * 100)
    else:
        history_score = 70  # Default se SIEM non disponibile
    components['history_score'] = history_score
    
    # 3. ANOMALY SCORE (25%) - Eventi di sicurezza recenti
    security_events = siem_client.get_security_events(source_ip)
    if security_events > 10:
        anomaly_score = 20
    elif security_events > 5:
        anomaly_score = 50
    elif security_events > 0:
        anomaly_score = 70
    else:
        anomaly_score = 100
    components['anomaly_score'] = anomaly_score
    
    # 4. CONTEXT SCORE (20%) - Tempo, rete, etc.
    # Base context starts at 70, bonuses/penalties applied
    context_score = 70
    current_hour = datetime.now().hour
    is_blacklisted = False
    
    # Penalità fuori orario lavorativo
    if current_hour < POLICIES['time_restrictions']['business_hours']['start'] or \
       current_hour > POLICIES['time_restrictions']['business_hours']['end']:
        if not any(r in POLICIES['time_restrictions']['weekend_allowed_roles'] for r in user_roles):
            context_score -= 10
    
    # Network-based trust adjustments
    logger.info(f"Calculating context for IP: {source_ip}")
    
    # Production Network: +30 → context = 100
    if source_ip.startswith('172.28.4.'):
        context_score += 30
        logger.info(f"Production network bonus: +30, context_score={context_score}")
    # Development Network: +25 → context = 95
    elif source_ip.startswith('172.28.5.'):
        context_score += 25
        logger.info(f"Development network bonus: +25, context_score={context_score}")
    # Internal Network: +20 → context = 90
    elif source_ip.startswith('172.28.2.'):
        context_score += 20
        logger.info(f"Internal network bonus: +20, context_score={context_score}")
    # DMZ Network: +15 → context = 85
    elif source_ip.startswith('172.28.3.'):
        context_score += 15
        logger.info(f"DMZ network bonus: +15, context_score={context_score}")
    # External Network
    elif source_ip.startswith('172.28.1.'):
        # Check if blacklisted first
        if source_ip in POLICIES['ip_blacklist']:
            context_score = 0  # Zero context for blacklisted
            is_blacklisted = True
            logger.warning(f"BLACKLISTED IP: {source_ip}, context_score=0")
        # Check if whitelisted (specific IPs)
        elif source_ip == '172.28.1.100' or source_ip == '172.28.1.50':
            context_score -= 15  # context = 55
            logger.info(f"Whitelisted external IP: {source_ip}, penalty: -15, context_score={context_score}")
        else:
            context_score -= 40  # context = 30
            logger.warning(f"Unknown external IP: {source_ip}, penalty: -40, context_score={context_score}")
    
    components['context_score'] = max(0, min(100, context_score))
    components['source_ip'] = source_ip
    components['is_blacklisted'] = is_blacklisted
    
    # For blacklisted IPs, heavily penalize all scores
    if is_blacklisted:
        components['base_trust'] = min(components['base_trust'], 30)
        components['history_score'] = 0
        components['anomaly_score'] = 0
    
    # CALCOLO FINALE
    weights = {'base_trust': 0.30, 'history_score': 0.25, 'anomaly_score': 0.25, 'context_score': 0.20}
    final_score = sum(components[k] * weights[k] for k in weights)
    
    return round(final_score, 2), components

# ============================================================================
# VALUTAZIONE POLICY
# ============================================================================
def evaluate_request(request_data):
    """
    Valuta una richiesta di accesso secondo le policy Zero Trust

    Formati di input supportati:

    {
        "subject": {"username": "...", "roles": [...], "token": "..."},
        "device": {"ip": "...", "hostname": "...", "network": "..."},
        "resource": {"type": "...", "action": "...", "path": "..."},
        "context": {"timestamp": "...", "user_agent": "..."}
    }

    {
        "username": "...",
        "user_roles": [...],
        "source_ip": "...",
        "resource": "...",
        "action": "...",
        "context": {...}
    }

    Output: {
        "decision": "allow" | "deny",
        "trust_score": float,
        "reason": "...",
        "components": {...}
    }
    """

    if 'subject' in request_data and isinstance(request_data.get('subject'), dict):
        subject = request_data.get('subject', {})
        device = request_data.get('device', {})
        resource_data = request_data.get('resource', {})
        context = request_data.get('context', {})

        username = subject.get('username', 'anonymous')
        user_roles = subject.get('roles', [])
        source_ip = device.get('ip', 'unknown')
        resource_type = resource_data.get('type', 'unknown') if isinstance(resource_data, dict) else str(resource_data)
        action = resource_data.get('action', 'read') if isinstance(resource_data, dict) else 'read'
    else:
        username = request_data.get('username', 'anonymous')
        user_roles = request_data.get('user_roles', request_data.get('roles', []))
        source_ip = request_data.get('source_ip', request_data.get('ip', 'unknown'))
        resource_type = request_data.get('resource', 'unknown')
        action = request_data.get('action', 'read')
        context = request_data.get('context', {})
    
    logger.info(f"Evaluating request: user={username}, ip={source_ip}, resource={resource_type}, action={action}")
    
    # -------------------------------------------------------------------------
    # CHECK: Blacklist IP
    # -------------------------------------------------------------------------
    if source_ip in POLICIES['ip_blacklist']:
        decision = {
            "decision": "deny",
            "trust_score": 0,
            "reason": f"IP {source_ip} is blacklisted",
            "components": {"ip_check": "BLOCKED"}
        }
        siem_client.log_decision({**decision, "username": username, "source_ip": source_ip})
        return decision
    
    # -------------------------------------------------------------------------
    # CHECK: Calcolo Trust Score
    # -------------------------------------------------------------------------
    trust_score, components = calculate_trust_score(username, source_ip, user_roles, context)
    
    # -------------------------------------------------------------------------
    # CHECK: Trust Score Minimo per Risorsa
    # -------------------------------------------------------------------------
    resource_policy = POLICIES['resource_access'].get(resource_type, {"min_trust": 60, "roles": []})
    min_trust = resource_policy['min_trust']
    allowed_roles = resource_policy['roles']
    
    if trust_score < min_trust:
        decision = {
            "decision": "deny",
            "trust_score": trust_score,
            "reason": f"Trust score {trust_score} below minimum {min_trust} for resource {resource_type}",
            "components": components
        }
        siem_client.log_decision({**decision, "username": username, "source_ip": source_ip})
        return decision
    
    # -------------------------------------------------------------------------
    # CHECK: Accesso Basato su Ruoli (RBAC)
    # -------------------------------------------------------------------------
    if allowed_roles and not any(r in allowed_roles for r in user_roles):
        decision = {
            "decision": "deny",
            "trust_score": trust_score,
            "reason": f"User roles {user_roles} not authorized for resource {resource_type}",
            "components": components
        }
        siem_client.log_decision({**decision, "username": username, "source_ip": source_ip})
        return decision
    
    # -------------------------------------------------------------------------
    # CHECK: Permesso per Azione
    # -------------------------------------------------------------------------
    for role in user_roles:
        role_perms = POLICIES['roles_permissions'].get(role, {})
        if role_perms.get(action, False):
            break
    else:
        if user_roles:  # Il ruolo non permette l'azione
            decision = {
                "decision": "deny",
                "trust_score": trust_score,
                "reason": f"Action '{action}' not permitted for user roles",
                "components": components
            }
            siem_client.log_decision({**decision, "username": username, "source_ip": source_ip})
            return decision
    
    # -------------------------------------------------------------------------
    # ALLOW
    # -------------------------------------------------------------------------
    decision = {
        "decision": "allow",
        "trust_score": trust_score,
        "reason": "All policy checks passed",
        "components": components,
        "access_level": "full" if trust_score >= 80 else "standard" if trust_score >= 60 else "limited"
    }
    siem_client.log_decision({**decision, "username": username, "source_ip": source_ip, "resource": resource_type})
    
    logger.info(f"Decision: ALLOW - user={username}, trust={trust_score}, resource={resource_type}")
    return decision

# ============================================================================
# API ENDPOINTS
# ============================================================================
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "PDP", "timestamp": datetime.now().isoformat()})

@app.route('/evaluate', methods=['POST'])
def evaluate():
    """Endpoint principale per valutazione policy"""
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({"error": "No data provided"}), 400
        
        decision = evaluate_request(request_data)
        return jsonify(decision)
    
    except Exception as e:
        logger.error(f"Evaluation error: {e}")
        return jsonify({"error": str(e), "decision": "deny"}), 500

@app.route('/trust-score', methods=['POST'])
def get_trust_score():
    """Endpoint per ottenere solo il trust score"""
    try:
        data = request.get_json()
        username = data.get('username', 'anonymous')
        source_ip = data.get('source_ip', 'unknown')
        user_roles = data.get('roles', [])
        
        score, components = calculate_trust_score(username, source_ip, user_roles, {})
        return jsonify({
            "username": username,
            "trust_score": score,
            "components": components
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/policies', methods=['GET'])
def get_policies():
    """Restituisce le policy attive (per debug)"""
    return jsonify(POLICIES)

# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("PDP - Policy Decision Point")
    logger.info("Zero Trust Architecture - TechCorp")
    logger.info("=" * 60)
    logger.info(f"SIEM: {SPLUNK_HOST}:{SPLUNK_PORT}")
    
    app.run(host='0.0.0.0', port=5000, debug=False)

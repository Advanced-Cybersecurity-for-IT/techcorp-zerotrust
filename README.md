# 🛡️ TechCorp Zero Trust Architecture

## Progetto di Sicurezza Avanzata
**Università Politecnica delle Marche** — Dipartimento di Ingegneria dell'Informazione  
**Corso:** Sicurezza Avanzata | **Docente:** Prof. Luca Spalazzi | **A.A. 2024/2025**

---

## 📑 Indice

1. [Introduzione](#-introduzione)
2. [Cos'è Zero Trust](#-cosè-zero-trust)
3. [Architettura del Sistema](#-architettura-del-sistema)
4. [Componenti Implementati](#-componenti-implementati)
   - [PDP - Policy Decision Point](#1-pdp---policy-decision-point)
   - [PEP - Policy Enforcement Point](#2-pep---policy-enforcement-point)
   - [Snort IDS - Intrusion Detection System](#3-snort-ids---intrusion-detection-system)
   - [Firewall Multi-Livello](#4-firewall-multi-livello)
   - [Splunk SIEM](#5-splunk-siem)
   - [PostgreSQL Database](#6-postgresql-database)
   - [Keycloak Identity Provider](#7-keycloak-identity-provider)
5. [Il Trust Score: Cuore del Sistema](#-il-trust-score-cuore-del-sistema)
6. [Topologia di Rete](#-topologia-di-rete)
7. [Utenti e Ruoli Aziendali](#-utenti-e-ruoli-aziendali)
8. [Scenari di Test](#-scenari-di-test)
9. [Guida all'Installazione](#-guida-allinstallazione)
10. [Test e Validazione](#-test-e-validazione)
11. [Monitoraggio su Splunk](#-monitoraggio-su-splunk)
12. [Troubleshooting](#-troubleshooting)
13. [Riferimenti](#-riferimenti)

---

## 📖 Introduzione

Questo progetto implementa un'**architettura Zero Trust completa** per un'azienda fittizia chiamata **TechCorp**. L'obiettivo è dimostrare come i principi Zero Trust possano essere applicati in un ambiente enterprise per proteggere risorse sensibili.

### Obiettivi del Progetto

1. **Implementare i componenti fondamentali** di un'architettura Zero Trust (PDP, PEP, IDS, Firewall, SIEM)
2. **Calcolare dinamicamente il Trust Score** basandosi su molteplici fattori
3. **Integrare i tool richiesti**: Splunk, IpTables, Squid, Snort, PostgreSQL
4. **Simulare scenari realistici** di accesso autorizzato e non autorizzato

---

## 🔐 Cos'è Zero Trust

### Il Paradigma "Never Trust, Always Verify"

L'architettura **Zero Trust** abbandona il concetto tradizionale di "perimetro sicuro" (castle-and-moat) in favore di un modello dove:

> **Nessuna entità è considerata affidabile a priori**, indipendentemente dalla sua posizione nella rete.

### Principi Fondamentali

| Principio | Descrizione | Implementazione nel Progetto |
|-----------|-------------|------------------------------|
| **Verifica Esplicita** | Ogni richiesta deve essere autenticata e autorizzata | PEP verifica token JWT + PDP calcola Trust Score |
| **Minimo Privilegio** | Accesso limitato solo a ciò che è necessario | ACL per ruolo + soglie Trust Score per risorsa |
| **Assume Breach** | Progettare come se la rete fosse già compromessa | IDS inline, logging completo, segmentazione rete |

### Differenza con Approcci Tradizionali

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    APPROCCIO TRADIZIONALE (Perimetrale)                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│    INTERNET ──── [Firewall] ──── RETE INTERNA (tutti trusted)          │
│                                                                         │
│    ❌ Una volta dentro, accesso libero                                  │
│    ❌ Movimento laterale possibile                                      │
│    ❌ Insider threat non gestito                                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    APPROCCIO ZERO TRUST (Questo Progetto)               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│    OGNI RICHIESTA ──── [PEP] ──── [IDS] ──── [PDP] ──── RISORSA        │
│                           │         │          │                        │
│                           └─────────┴──────────┴──── [SIEM]            │
│                                                                         │
│    ✅ Verifica continua ad ogni richiesta                               │
│    ✅ Trust Score dinamico basato su contesto                           │
│    ✅ Logging centralizzato per analisi                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ Architettura del Sistema

### Diagramma Architetturale Completo

```
                                    ┌──────────────────────────────────────────────────────────────┐
                                    │                         DBMS                                  │
                                    │                     (PostgreSQL)                              │
                                    └──────────────────────────────────────────────────────────────┘
                                                              │
                                                              │ log
                                                              ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────────┐
│    Firewall      │  │    Firewall      │  │       IDS        │  │      Logging Service         │
│  Network Level   │  │ Application Level│  │     (Snort)      │  │        (Splunk)              │
│   (iptables)     │  │    (Squid)       │  │                  │  │                              │
└────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  └──────────────────────────────┘
         │                     │                     │                           ▲
         │ log file            │ log file            │ log file                  │
         └─────────────────────┴─────────────────────┴───────────────────────────┘
                                              │
                                              │ history
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      CONTROL PLANE                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐    │
│  │                           Policy Decision Point (PDP)                                    │    │
│  │                                                                                          │    │
│  │   • Riceve richiesta (s, d, n, o, r) dal PEP                                            │    │
│  │   • Interroga SIEM per history utente                                                   │    │
│  │   • Calcola Trust Score dinamico                                                        │    │
│  │   • Verifica policy (ACL, ruoli, soglie)                                                │    │
│  │   • Restituisce decisione: ALLOW / DENY                                                 │    │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘    │
│                                              │                                                   │
│                              Request(s,d,n,o,r) │ approval/reject                                │
│                                              ▼                                                   │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
                                              │
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       DATA PLANE                                                 │
│                                              │                                                   │
│  ┌───────────┐    Request     ┌─────────────────────────────┐    Decision    ┌───────────────┐  │
│  │           │   (s,d,n,o,r)  │                             │    Applied     │    Access     │  │
│  │   User    │ ─────────────► │  Policy Enforcement Point   │ ─────────────► │   Control     │  │
│  │           │                │           (PEP)             │                │   Service     │  │
│  └───────────┘                └─────────────────────────────┘                └───────┬───────┘  │
│       │                                                                              │          │
│       │                                                                              │ access   │
│       │                                                                              ▼          │
│       │                                                                      ┌─────────────┐   │
│       │◄─────────────────────────── Reply ───────────────────────────────────│  Resource   │   │
│                                                                              └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

Legenda:
  s = Subject (utente)
  d = Device (dispositivo)
  n = Network (rete di provenienza)
  o = Object (risorsa richiesta)
  r = Request type (azione: read, write, delete)
```

### Flusso di una Richiesta

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                        SEQUENZA COMPLETA DI UNA RICHIESTA                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  USER                FIREWALL L3        FIREWALL L7           IDS              PEP              PDP             SIEM            DATABASE
   │                  (iptables)          (Squid)            (Snort)                                                              
   │                      │                  │                  │                │                │                │                │
   │  1. HTTP Request     │                  │                  │                │                │                │                │
   │─────────────────────►│                  │                  │                │                │                │                │
   │                      │                  │                  │                │                │                │                │
   │                      │  2. Check IP     │                  │                │                │                │                │
   │                      │  Blacklist/      │                  │                │                │                │                │
   │                      │  Whitelist       │                  │                │                │                │                │
   │                      │─────────────────►│                  │                │                │                │                │
   │                      │                  │                  │                │                │                │                │
   │                      │      LOG ────────┼──────────────────┼────────────────┼────────────────┼────────────────►                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │  3. Check        │                │                │                │                │
   │                      │                  │  Domain/Host     │                │                │                │                │
   │                      │                  │─────────────────►│                │                │                │                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │      LOG ────────┼────────────────┼────────────────┼────────────────►                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │  4. Deep       │                │                │                │
   │                      │                  │                  │  Packet        │                │                │                │
   │                      │                  │                  │  Inspection    │                │                │                │
   │                      │                  │                  │───────────────►│                │                │                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │      LOG ──────┼────────────────┼────────────────►                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │  5. Request    │                │                │
   │                      │                  │                  │                │  (s,d,n,o,r)   │                │                │
   │                      │                  │                  │                │───────────────►│                │                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │                │  6. Query      │                │
   │                      │                  │                  │                │                │  History(s,d,n)│                │
   │                      │                  │                  │                │                │───────────────►│                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │                │◄───────────────│                │
   │                      │                  │                  │                │                │  History data  │                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │                │  7. Compute    │                │
   │                      │                  │                  │                │                │  Trust Score   │                │
   │                      │                  │                  │                │                │  (t)           │                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │                │  8. Check      │                │
   │                      │                  │                  │                │                │  t ≥ threshold │                │
   │                      │                  │                  │                │                │  (s,o,r)       │                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │◄───────────────│                │                │
   │                      │                  │                  │                │  9. Decision   │                │                │
   │                      │                  │                  │                │  (allow/deny)  │                │                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │                │      LOG ──────►                │
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │  [IF ALLOW]    │                │                │
   │                      │                  │                  │                │  10. Query DB  │                │                │
   │                      │                  │                  │                │────────────────┼────────────────┼───────────────►│
   │                      │                  │                  │                │                │                │                │
   │                      │                  │                  │                │◄───────────────┼────────────────┼────────────────│
   │                      │                  │                  │                │  11. Data      │                │                │
   │                      │                  │                  │                │                │                │                │
   │◄─────────────────────┼──────────────────┼──────────────────┼────────────────│                │                │                │
   │  12. Response        │                  │                  │                │                │                │                │
   │  (data or error)     │                  │                  │                │                │                │                │
   │                      │                  │                  │                │                │                │                │
```

---

## 🧩 Componenti Implementati

### 1. PDP - Policy Decision Point

**File:** `pdp/pdp.py`  
**Tecnologia:** Python Flask  
**Porta:** 5000  

Il **PDP** è il "cervello" del sistema Zero Trust. Riceve richieste dal PEP e decide se permettere o negare l'accesso.

#### Funzionalità Principali

```python
# Endpoint principale
POST /evaluate
{
    "subject": {"username": "m.rossi", "roles": ["ceo"]},
    "device": {"ip": "172.28.4.10", "network": "production"},
    "resource": {"type": "employees", "action": "read"},
    "context": {"timestamp": "2025-01-09T10:30:00"}
}

# Risposta
{
    "decision": "allow",
    "trust_score": 93.5,
    "reason": "All policy checks passed",
    "access_level": "full",
    "components": {
        "base_trust": 100,
        "history_score": 70,
        "anomaly_score": 100,
        "context_score": 100
    }
}
```

#### Processo Decisionale del PDP

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROCESSO DECISIONALE PDP                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  1. CHECK IP        │
            ┌──────│     BLACKLIST       │
            │      └─────────────────────┘
            │               │
     IP in Blacklist?       │ NO
            │               ▼
            │      ┌─────────────────────┐
            │      │  2. CALCULATE       │
            │      │    TRUST SCORE      │
            │      └─────────────────────┘
            │               │
            │               ▼
            │      ┌─────────────────────┐
            │      │  3. CHECK MINIMUM   │
            │      │  TRUST FOR RESOURCE │
            │      └─────────────────────┘
            │               │
            │        Trust < Min?
            │        │           │
            │       YES          NO
            │        │           │
            │        │           ▼
            │        │  ┌─────────────────────┐
            │        │  │  4. CHECK ROLE      │
            │        │  │     PERMISSION      │
            │        │  └─────────────────────┘
            │        │           │
            │        │    Role allowed?
            │        │     │          │
            │        │    NO         YES
            │        │     │          │
            │        │     │          ▼
            │        │     │  ┌─────────────────────┐
            │        │     │  │  5. CHECK ACTION    │
            │        │     │  │     PERMISSION      │
            │        │     │  └─────────────────────┘
            │        │     │          │
            │        │     │   Action allowed?
            │        │     │    │          │
            │        │     │   NO         YES
            ▼        ▼     ▼    │          │
     ┌──────────────────────────┘          │
     │                                     │
     ▼                                     ▼
┌─────────┐                         ┌─────────┐
│  DENY   │                         │  ALLOW  │
└─────────┘                         └─────────┘
```

#### Integrazione con SIEM (PDP come Client SIEM)

```python
class SIEMClient:
    """
    Il PDP interroga Splunk per ottenere la history dell'utente.
    Questo è fondamentale per il calcolo del Trust Score.
    """
    
    def query_user_history(self, username, hours=24):
        """
        Query: search index=zerotrust username="m.rossi" earliest=-24h
        Restituisce: successi, fallimenti, anomalie
        """
        search_query = f'search index=zerotrust username="{username}" earliest=-{hours}h'
        response = self.session.post(
            f"{self.base_url}/services/search/jobs",
            data={'search': search_query, 'output_mode': 'json'}
        )
        return response.json()
    
    def get_security_events(self, source_ip, hours=1):
        """
        Conta gli eventi di sicurezza recenti per l'IP.
        Usato per calcolare l'Anomaly Score.
        """
        search_query = f'search index=zerotrust source_ip="{source_ip}" (alert OR blocked) earliest=-{hours}h | stats count'
        # ...
```

---

### 2. PEP - Policy Enforcement Point

**File:** `pep/pep.js`  
**Tecnologia:** Node.js Express  
**Porta:** 8080  

Il **PEP** è il gateway che intercetta tutte le richieste e le valida prima di permettere l'accesso alle risorse.

#### Funzionalità Principali

1. **Estrazione informazioni utente** dal token JWT
2. **Analisi IDS** di ogni richiesta
3. **Consultazione PDP** per decisione
4. **Accesso al Database** come client DBMS
5. **Enforcement** della decisione

#### PEP come Client DBMS

```javascript
// Configurazione connessione PostgreSQL
const { Pool } = require('pg');
const pool = new Pool({
    host: 'postgres-db',
    port: 5432,
    user: 'techcorp_user',
    password: 'TechCorp2024!',
    database: 'techcorp_db'
});

// Esempio di accesso a risorsa protetta
app.get('/api/db/employees', async (req, res) => {
    // 1. Ottieni IP reale del client
    const sourceIP = getClientIP(req);
    
    // 2. Consulta PDP per decisione
    const decision = await consultPDP(
        req.userInfo.username,
        req.userInfo.roles,
        sourceIP,
        'employees',  // risorsa
        'read'        // azione
    );
    
    // 3. Enforce decisione
    if (decision.decision !== 'allow') {
        return res.status(403).json({
            error: 'Access denied',
            reason: decision.reason,
            trust_score: decision.trust_score
        });
    }
    
    // 4. Accesso al database (PEP è client DBMS)
    const data = await pool.query(
        'SELECT * FROM enterprise.employees WHERE is_active = true'
    );
    
    res.json({
        success: true,
        data: data.rows,
        trust_score: decision.trust_score
    });
});
```

#### Middleware IDS Integration

```javascript
const idsAnalysis = async (req, res, next) => {
    // Invia richiesta a Snort IDS per analisi
    const idsResult = await analyzeWithSnort(req);
    
    // Se IDS rileva attacco, blocca immediatamente
    if (idsResult.blocked) {
        return res.status(403).json({
            error: 'Request blocked by Intrusion Detection System',
            alerts: idsResult.alerts,
            blocked_by: 'Snort-IDS'
        });
    }
    
    next();
};
```

---

### 3. Snort IDS - Intrusion Detection System

**File:** `snort-ids/snort_ids.py`  
**Tecnologia:** Python Flask  
**Porta:** 9090  

Il **Snort IDS** analizza ogni richiesta in tempo reale per rilevare pattern di attacco.

#### Regole Implementate

| ID | Nome | Severità | Pattern | Azione |
|----|------|----------|---------|--------|
| **SQLI-001** | SQL Injection - UNION | 🔴 Critical | `union\s+(all\s+)?select` | Block |
| **SQLI-002** | SQL Injection - Boolean | 🔴 Critical | `' or '1'='1` | Block |
| **SQLI-003** | SQL Injection - Time-based | 🔴 Critical | `sleep\(`, `benchmark\(` | Block |
| **XSS-001** | XSS - Script Tag | 🟠 High | `<script>`, `javascript:` | Block |
| **XSS-002** | XSS - Event Handler | 🟠 High | `onerror=`, `onload=` | Block |
| **TRAV-001** | Directory Traversal | 🟠 High | `../`, `..\\` | Block |
| **TRAV-002** | Sensitive File Access | 🔴 Critical | `/etc/passwd`, `.htaccess` | Block |
| **CMD-001** | Command Injection | 🔴 Critical | `; ls`, `; cat` | Block |
| **SCAN-001** | Port Scan Detection | 🟡 Medium | `nmap`, `masscan` | Alert |
| **SCAN-002** | Vulnerability Scanner | 🟠 High | `nikto`, `sqlmap` | Alert |
| **UA-001** | Malicious Bot | 🟡 Medium | `sqlmap`, `havij` | Block |
| **BRUTE-001** | Login Brute Force | 🟠 High | threshold: 5 in 60s | Block |

#### Processo di Analisi

```
┌─────────────────────────────────────────────────────────────────┐
│                    SNORT IDS - PACKET ANALYSIS                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Receive Packet     │
                   │  from PEP           │
                   └─────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Extract Fields:    │
                   │  - payload          │
                   │  - uri              │
                   │  - user_agent       │
                   │  - method           │
                   │  - headers          │
                   └─────────────────────┘
                              │
                              ▼
         ┌────────────────────┴────────────────────┐
         │                                         │
         ▼                                         ▼
┌─────────────────────┐                 ┌─────────────────────┐
│  SIGNATURE-BASED    │                 │  DEEP PACKET        │
│  DETECTION          │                 │  INSPECTION         │
│                     │                 │                     │
│  - Regex matching   │                 │  - Entropy calc     │
│  - Pattern search   │                 │  - Encoding detect  │
│  - User-Agent check │                 │  - Anomaly detect   │
└─────────────────────┘                 └─────────────────────┘
         │                                         │
         └────────────────────┬────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Generate Alerts    │
                   │  if matches found   │
                   └─────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Log to SIEM        │
                   │  (Splunk)           │
                   └─────────────────────┘
                              │
                              ▼
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
     ┌─────────────────┐             ┌─────────────────┐
     │  action: block  │             │  action: alert  │
     │  → Block request│             │  → Continue     │
     └─────────────────┘             └─────────────────┘
```

#### Deep Packet Inspection

```python
def deep_inspection(packet_data):
    """
    Analisi avanzata del payload per rilevare:
    - Payload codificati (URL encoding, HTML entities)
    - Contenuto base64 sospetto
    - Caratteri di controllo binari
    - Alta entropia (possibile offuscamento/encryption)
    """
    results = {'anomalies': [], 'risk_score': 0}
    payload = packet_data.get('payload', '')
    
    # Check URL encoding
    if '%' in payload or '&#' in payload:
        results['anomalies'].append('Encoded payload detected')
        results['risk_score'] += 20
    
    # Check base64
    if re.search(r'^[A-Za-z0-9+/]{50,}={0,2}$', payload):
        results['anomalies'].append('Possible base64 encoded payload')
        results['risk_score'] += 15
    
    # Check binary characters
    if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', payload):
        results['anomalies'].append('Binary/control characters in payload')
        results['risk_score'] += 25
    
    # Check entropy (Shannon entropy)
    if len(payload) > 100:
        entropy = calculate_entropy(payload)
        if entropy > 5.5:  # High entropy = suspicious
            results['anomalies'].append(f'High entropy payload ({entropy:.2f})')
            results['risk_score'] += 30
    
    return results
```

---

### 4. Firewall Multi-Livello

#### 4.1 IpTables - Firewall Layer 3 (Network Level)

**File:** `iptables-firewall/firewall.py`  
**Porta:** 8888  

Opera a livello di rete, filtrando pacchetti basandosi su indirizzi IP.

```python
# Regole di filtraggio
BLACKLIST = ['172.28.1.200', '172.28.1.250', '172.28.1.60']

def check_packet(src_ip, dst_ip):
    # 1. Check blacklist
    if src_ip in BLACKLIST:
        return False, f"Source {src_ip} blacklisted"
    
    # 2. Allow internal networks
    if src_ip.startswith('172.28.2.'):  # Internal
        return True, "Internal network allowed"
    if src_ip.startswith('172.28.3.'):  # DMZ
        return True, "DMZ allowed"
    if src_ip.startswith('172.28.4.'):  # Production
        return True, "Production allowed"
    if src_ip.startswith('172.28.5.'):  # Development
        return True, "Development allowed"
    
    # 3. Whitelist specific external
    if src_ip == '172.28.1.100':
        return True, "Whitelisted external"
    
    # 4. Block unknown external
    if src_ip.startswith('172.28.1.'):
        return False, "External blocked by default"
    
    return True, "Default allow"
```

#### 4.2 Squid - Firewall Layer 7 (Application Level)

**File:** `squid-proxy/squid.py`  
**Porta:** 3128  

Opera a livello applicativo, filtrando richieste HTTP basandosi su domini e hostname.

```python
# Domini bloccati
BLACKLIST_DOMAINS = [
    'external-blocked-server',
    'blocked-server',
    'malware-site.com',
    'phishing-site.com',
    'hacker-tools.org'
]

def is_blocked(self, host):
    """Verifica se il dominio è nella blacklist"""
    for blocked in BLACKLIST_DOMAINS:
        if blocked in host.lower():
            return True
    return False
```

---

### 5. Splunk SIEM

**Tecnologia:** Splunk Enterprise  
**Porta Web:** 8000  
**Porta HEC:** 8088  

Il **SIEM** (Security Information and Event Management) raccoglie e correla tutti i log del sistema.

#### Sorgenti di Log

| Componente | Sourcetype | Dati Registrati |
|------------|------------|-----------------|
| PDP | `pdp_decision` | Decisioni, Trust Score, motivo, utente |
| PEP | `pep_access` | Richieste, IP, risorsa, risposta |
| Snort IDS | `snort_ids` | Alert, regola, severità, payload |
| iptables | `iptables_log` | IP sorgente/dest, azione (ACCEPT/DROP) |
| Squid | `squid_access` | URL, dominio, azione |

#### Query Splunk Utili

```spl
# Dashboard: Tutti gli eventi Zero Trust
index=zerotrust | stats count by sourcetype

# Decisioni PDP nelle ultime 24 ore
index=zerotrust sourcetype=pdp_decision 
| table timestamp username decision trust_score reason

# Alert Snort per severità
index=zerotrust sourcetype=snort_ids 
| stats count by severity rule_name
| sort - count

# Accessi negati per utente
index=zerotrust decision=deny 
| stats count by username reason
| sort - count

# Trust Score medio per utente
index=zerotrust sourcetype=pdp_decision decision=allow
| stats avg(trust_score) as avg_trust by username
| sort - avg_trust

# Timeline attacchi rilevati
index=zerotrust sourcetype=snort_ids action=block
| timechart count by rule_name
```

---

### 6. PostgreSQL Database

**Porta:** 5432  
**Schema:** `enterprise`  

Database aziendale con dati sensibili protetti dall'architettura Zero Trust.

#### Schema delle Tabelle

```sql
enterprise
├── departments      -- Dipartimenti aziendali
├── employees        -- Dipendenti (dati sensibili)
├── customers        -- Clienti (dati commerciali)
├── products         -- Catalogo prodotti
├── orders           -- Ordini cliente
├── projects         -- Progetti attivi
└── audit_log        -- Log accessi (integrato con SIEM)
```

#### Dati di Esempio

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         ENTERPRISE DATABASE                               │
├────────────────┬────────────────┬──────────────────┬─────────────────────┤
│   employees    │   customers    │     orders       │     projects        │
├────────────────┼────────────────┼──────────────────┼─────────────────────┤
│ TC001 M.Rossi  │ CL001 Innovatech│ ORD-2024-001    │ PRJ-001 Cloud Migr  │
│ TC002 L.Bianchi│ CL002 GlobalSys │ ORD-2024-002    │ PRJ-002 Security    │
│ TC003 G.Ferrari│ CL003 DigitalF  │ ORD-2024-003    │ PRJ-003 ERP Integ   │
│ TC004 A.Romano │ CL004 SmartSol  │ ORD-2024-004    │ PRJ-004 Mobile App  │
│ ...            │ ...             │ ...              │ ...                 │
└────────────────┴────────────────┴──────────────────┴─────────────────────┘
```

---

### 7. Keycloak Identity Provider

**Porta:** 8180  
**Realm:** `techcorp`  

Sistema di identity management che gestisce autenticazione e ruoli.

#### Funzionalità

- **OAuth2/OIDC** standard per autenticazione
- **Brute Force Protection** abilitata (30 tentativi max)
- **Ruoli Realm-level** per RBAC
- **Token JWT** con claims personalizzati

---

## 📊 Il Trust Score: Cuore del Sistema

Il **Trust Score** è un valore numerico (0-100) che rappresenta il livello di fiducia calcolato dinamicamente per ogni richiesta.

### Formula di Calcolo

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRUST SCORE FORMULA                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Trust Score = (Base Trust    × 0.30) +                                    │
│                 (History Score × 0.25) +                                    │
│                 (Anomaly Score × 0.25) +                                    │
│                 (Context Score × 0.20)                                      │
│                                                                              │
│   Range: 0 - 100                                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Componenti del Trust Score

#### 1. Base Trust (30%) - Dal Ruolo Utente

Il **Base Trust** è determinato dal ruolo dell'utente nell'organizzazione.

| Ruolo | Base Trust | Motivazione |
|-------|------------|-------------|
| `ceo` | 100 | Massimo livello di responsabilità e fiducia |
| `cto` | 95 | Accesso tecnico privilegiato |
| `hr_manager` | 85 | Gestisce dati sensibili dei dipendenti |
| `sales_manager` | 80 | Accesso a dati clienti e commerciali |
| `developer` | 75 | Accesso a codice sorgente |
| `analyst` | 70 | Accesso in sola lettura |
| `default` | 50 | Utente non riconosciuto |

```python
role_trust = {
    "ceo": 100, "cto": 95, "hr_manager": 85, 
    "sales_manager": 80, "developer": 75, "analyst": 70, 
    "default": 50
}
max_role_trust = max([role_trust.get(r, 50) for r in user_roles], default=50)
```

#### 2. History Score (25%) - Dal SIEM

Il **History Score** è calcolato interrogando Splunk per lo storico dell'utente.

```python
def calculate_history_score(username):
    """
    Query SIEM per:
    - Numero di accessi riusciti nelle ultime 24h
    - Numero di accessi falliti nelle ultime 24h
    - Anomalie rilevate
    """
    history = siem_client.query_user_history(username, hours=24)
    
    if history:
        failed = history.get('failed_count', 0)
        success = history.get('success_count', 1)
        
        # Rapporto successi/totale
        history_score = (success / (success + failed)) * 100
        return min(100, history_score)
    
    return 70  # Default se SIEM non disponibile
```

| Scenario | History Score |
|----------|---------------|
| 100% successi, 0 fallimenti | 100 |
| 90% successi, 10% fallimenti | 90 |
| 50% successi, 50% fallimenti | 50 |
| SIEM non disponibile | 70 (default) |

#### 3. Anomaly Score (25%) - Eventi di Sicurezza

L'**Anomaly Score** penalizza IP che hanno generato alert di sicurezza recenti.

```python
def calculate_anomaly_score(source_ip):
    """
    Query SIEM per eventi sicurezza dell'IP nell'ultima ora
    """
    security_events = siem_client.get_security_events(source_ip, hours=1)
    
    if security_events > 10:
        return 20   # Molti alert → alta penalità
    elif security_events > 5:
        return 50   # Alert moderati → media penalità
    elif security_events > 0:
        return 70   # Pochi alert → leggera penalità
    else:
        return 100  # Nessun alert → nessuna penalità
```

| Eventi Sicurezza (1h) | Anomaly Score |
|-----------------------|---------------|
| 0 | 100 |
| 1-5 | 70 |
| 6-10 | 50 |
| >10 | 20 |

#### 4. Context Score (20%) - Rete, Tempo, Dispositivo

Il **Context Score** valuta il contesto della richiesta.

```python
def calculate_context_score(source_ip, user_roles, current_hour):
    """
    Valuta:
    - Rete di provenienza (bonus/malus)
    - Orario lavorativo
    - Dispositivo (future)
    """
    context_score = 70  # Base
    
    # === NETWORK TRUST ===
    
    # Production Network: massima fiducia
    if source_ip.startswith('172.28.4.'):
        context_score += 30  # → 100
    
    # Development Network: alta fiducia
    elif source_ip.startswith('172.28.5.'):
        context_score += 25  # → 95
    
    # Internal Network
    elif source_ip.startswith('172.28.2.'):
        context_score += 20  # → 90
    
    # DMZ Network
    elif source_ip.startswith('172.28.3.'):
        context_score += 15  # → 85
    
    # External Network
    elif source_ip.startswith('172.28.1.'):
        # Check blacklist
        if source_ip in ['172.28.1.200', '172.28.1.250']:
            context_score = 0  # BLACKLISTED
        # Check whitelist
        elif source_ip == '172.28.1.100':
            context_score -= 15  # → 55 (penalità ma permesso)
        else:
            context_score -= 40  # → 30 (sconosciuto)
    
    # === TIME TRUST ===
    
    # Fuori orario lavorativo (8-20): penalità
    if current_hour < 8 or current_hour > 20:
        # CEO e CTO possono lavorare sempre
        if not any(r in ['ceo', 'cto'] for r in user_roles):
            context_score -= 10
    
    return max(0, min(100, context_score))
```

| Rete | IP Range | Context Score |
|------|----------|---------------|
| Production | 172.28.4.0/24 | 100 (+30) |
| Development | 172.28.5.0/24 | 95 (+25) |
| Internal | 172.28.2.0/24 | 90 (+20) |
| DMZ | 172.28.3.0/24 | 85 (+15) |
| External Whitelist | 172.28.1.100 | 55 (-15) |
| External Unknown | 172.28.1.x | 30 (-40) |
| **Blacklist** | 172.28.1.200/250 | **0** |

### Esempio di Calcolo Completo

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   ESEMPIO: CEO (m.rossi) da Production Network (172.28.4.10)                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Ruolo: CEO                                                                │
│   IP: 172.28.4.10 (Production)                                              │
│   Orario: 10:30 (business hours)                                            │
│   Security Events: 0                                                        │
│   History: 95% successi                                                     │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Base Trust    = 100 (CEO)                    × 0.30 = 30.00        │   │
│   │  History Score = 95                           × 0.25 = 23.75        │   │
│   │  Anomaly Score = 100 (0 eventi)               × 0.25 = 25.00        │   │
│   │  Context Score = 100 (Production + bus.hrs)   × 0.20 = 20.00        │   │
│   │  ─────────────────────────────────────────────────────────────────  │   │
│   │  TRUST SCORE   = 30.00 + 23.75 + 25.00 + 20.00 = 98.75             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Decisione: ✅ ALLOW (Trust 98.75 ≥ soglia 80 per full access)            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│   ESEMPIO: Developer (p.ferrari) da External Whitelist (172.28.1.100)       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Ruolo: Developer                                                          │
│   IP: 172.28.1.100 (External Whitelist)                                     │
│   Orario: 22:00 (fuori orario)                                              │
│   Security Events: 2                                                        │
│   History: 80% successi                                                     │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Base Trust    = 75 (Developer)               × 0.30 = 22.50        │   │
│   │  History Score = 80                           × 0.25 = 20.00        │   │
│   │  Anomaly Score = 70 (2 eventi)                × 0.25 = 17.50        │   │
│   │  Context Score = 45 (55 ext - 10 fuori orario)× 0.20 =  9.00        │   │
│   │  ─────────────────────────────────────────────────────────────────  │   │
│   │  TRUST SCORE   = 22.50 + 20.00 + 17.50 + 9.00 = 69.00              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Decisione: ⚠️ ALLOW con LIMITED ACCESS (Trust 69 ≥ soglia 60)            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│   ESEMPIO: Attacker da Blacklisted IP (172.28.1.200)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Ruolo: (nessuno)                                                          │
│   IP: 172.28.1.200 (BLACKLISTED)                                            │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Base Trust    = 30 (penalizzato)             × 0.30 =  9.00        │   │
│   │  History Score = 0 (blacklisted)              × 0.25 =  0.00        │   │
│   │  Anomaly Score = 0 (blacklisted)              × 0.25 =  0.00        │   │
│   │  Context Score = 0 (blacklisted)              × 0.20 =  0.00        │   │
│   │  ─────────────────────────────────────────────────────────────────  │   │
│   │  TRUST SCORE   = 9.00 + 0.00 + 0.00 + 0.00 = 9.00                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Decisione: ❌ DENY (Trust 9 < soglia 40 minima)                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Soglie di Accesso per Risorsa

| Risorsa | Trust Minimo | Ruoli Autorizzati |
|---------|--------------|-------------------|
| `stats` | 40 | Tutti |
| `employees` | 50 | ceo, cto, hr_manager, developer, analyst |
| `projects` | 50 | ceo, cto, developer, analyst |
| `customers` | 60 | ceo, cto, sales_manager, analyst |
| `orders` | 60 | ceo, cto, sales_manager, analyst |
| `audit` | 80 | ceo, cto (solo admin) |

### Livelli di Accesso

| Trust Score | Livello | Descrizione |
|-------------|---------|-------------|
| ≥ 80 | 🟢 **Full Access** | Accesso completo a tutte le funzionalità |
| 60-79 | 🟡 **Standard Access** | Accesso normale con alcune restrizioni |
| 40-59 | 🟠 **Limited Access** | Accesso limitato, solo operazioni base |
| < 40 | 🔴 **Denied** | Accesso completamente negato |

---

## 🌐 Topologia di Rete

### Mappa Completa

```
                         ┌─────────────────────────────────────────────────────────┐
                         │                   EXTERNAL NETWORK                       │
                         │                    172.28.1.0/24                         │
                         │                                                          │
                         │    ┌───────────────┐  ┌───────────────┐  ┌────────────┐ │
                         │    │ allowed-server│  │blocked-server │  │ malicious  │ │
                         │    │   .50         │  │    .60        │  │   .250     │ │
                         │    │ ✅ Whitelist  │  │ ❌ Blacklist  │  │ 🚫 Block   │ │
                         │    └───────┬───────┘  └───────┬───────┘  └──────┬─────┘ │
                         │            │                  │                 │       │
                         │    ┌───────────────┐  ┌───────────────┐  ┌────────────┐ │
                         │    │external-allow │  │external-block │  │malicious   │ │
                         │    │   .100        │  │    .200       │  │ host       │ │
                         │    │ ⚠️ Trust: 55  │  │ ❌ Trust: 0   │  │🚫 Isolated │ │
                         │    └───────┬───────┘  └───────┬───────┘  └────────────┘ │
                         └────────────┼──────────────────┼─────────────────────────┘
                                      │                  │
                                      │                  │ (BLOCKED at L3)
┌─────────────────────────────────────┼──────────────────┼─────────────────────────────────┐
│                                     │      DMZ NETWORK │                                 │
│                                     │      172.28.3.0/24                                 │
│                                     │                  │                                 │
│         ┌──────────────┐    ┌───────┴────────┐    ┌────┴───────┐    ┌──────────────┐    │
│         │  Squid Proxy │    │      PEP       │    │  Keycloak  │    │  Snort IDS   │    │
│         │     .5       │    │     .10        │    │    .20     │    │     .2       │    │
│         │ 🦑 L7 Filter │    │ 🚪 Gateway     │    │ 🔑 IdP     │    │ 🛡️ Detection │    │
│         └──────────────┘    └───────┬────────┘    └────────────┘    └──────────────┘    │
│                                     │                                                    │
└─────────────────────────────────────┼────────────────────────────────────────────────────┘
                                      │
┌─────────────────────────────────────┼────────────────────────────────────────────────────┐
│                                     │  INTERNAL NETWORK                                  │
│                                     │    172.28.2.0/24                                   │
│                                     │                                                    │
│     ┌──────────────┐    ┌───────────┴──────────┐    ┌──────────────┐    ┌─────────────┐ │
│     │   iptables   │    │        PDP           │    │    Splunk    │    │  PostgreSQL │ │
│     │     .2       │    │        .20           │    │     .10      │    │     .40     │ │
│     │ 🔥 L3 Filter │    │ 🧠 Policy Decision   │    │ 📊 SIEM      │    │ 🗄️ Database │ │
│     └──────────────┘    └──────────────────────┘    └──────────────┘    └─────────────┘ │
│                                                                                          │
└──────────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────┐    ┌────────────────────────────────────┐
│        PRODUCTION NETWORK          │    │        DEVELOPMENT NETWORK         │
│          172.28.4.0/24             │    │          172.28.5.0/24             │
│                                    │    │                                    │
│     ┌────────────────────────┐     │    │     ┌────────────────────────┐     │
│     │       prod-host        │     │    │     │       dev-host         │     │
│     │         .10            │     │    │     │         .10            │     │
│     │                        │     │    │     │                        │     │
│     │   🏭 Context: +30      │     │    │     │   💻 Context: +25      │     │
│     │   Trust Score: ~93     │     │    │     │   Trust Score: ~84     │     │
│     │   Access: ✅ Full      │     │    │     │   Access: ✅ Full      │     │
│     └────────────────────────┘     │    │     └────────────────────────┘     │
│                                    │    │                                    │
└────────────────────────────────────┘    └────────────────────────────────────┘
```

### Riepilogo Networks

| Network | Subnet | Gateway | Scopo |
|---------|--------|---------|-------|
| **external_net** | 172.28.1.0/24 | 172.28.1.1 | Rete esterna, host non fidati |
| **dmz_net** | 172.28.3.0/24 | 172.28.3.1 | DMZ con servizi esposti |
| **internal_net** | 172.28.2.0/24 | 172.28.2.1 | Rete interna protetta |
| **prod_net** | 172.28.4.0/24 | 172.28.4.1 | Ambiente di produzione |
| **dev_net** | 172.28.5.0/24 | 172.28.5.1 | Ambiente di sviluppo |

---

## 👥 Utenti e Ruoli Aziendali

### Organigramma TechCorp

```
                              ┌─────────────────┐
                              │    m.rossi      │
                              │      CEO        │
                              │  Trust Base:100 │
                              └────────┬────────┘
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 │                     │                     │
        ┌────────┴────────┐   ┌────────┴────────┐   ┌────────┴────────┐
        │   l.bianchi     │   │    g.verdi      │   │    a.romano     │
        │      CTO        │   │   HR Manager    │   │  Sales Manager  │
        │  Trust Base: 95 │   │  Trust Base: 85 │   │  Trust Base: 80 │
        └────────┬────────┘   └─────────────────┘   └─────────────────┘
                 │
        ┌────────┴────────┐
        │   p.ferrari     │
        │   Developer     │
        │  Trust Base: 75 │
        └─────────────────┘
                                      ┌─────────────────┐
                                      │   e.colombo     │
                                      │    Analyst      │
                                      │  Trust Base: 70 │
                                      └─────────────────┘
```

### Credenziali di Accesso

| Username | Password | Ruolo | Email |
|----------|----------|-------|-------|
| **m.rossi** | CEO2024! | `ceo` | m.rossi@techcorp.local |
| **l.bianchi** | CTO2024! | `cto` | l.bianchi@techcorp.local |
| **g.verdi** | HR2024! | `hr_manager` | g.verdi@techcorp.local |
| **a.romano** | Sales2024! | `sales_manager` | a.romano@techcorp.local |
| **p.ferrari** | Dev2024! | `developer` | p.ferrari@techcorp.local |
| **e.colombo** | Analyst2024! | `analyst` | e.colombo@techcorp.local |

### Matrice dei Permessi (ACL)

```
┌─────────────────┬────────────┬────────────┬────────────┬────────────┬────────────┬────────────┐
│     Risorsa     │    CEO     │    CTO     │ HR Manager │Sales Manag.│ Developer  │  Analyst   │
├─────────────────┼────────────┼────────────┼────────────┼────────────┼────────────┼────────────┤
│  📊 Stats       │     ✅     │     ✅     │     ✅     │     ✅     │     ✅     │     ✅     │
│  👥 Employees   │     ✅     │     ✅     │     ✅     │     ❌     │     ✅     │     ✅     │
│  🏢 Customers   │     ✅     │     ✅     │     ❌     │     ✅     │     ❌     │     ✅     │
│  📦 Orders      │     ✅     │     ✅     │     ❌     │     ✅     │     ❌     │     ✅     │
│  💼 Projects    │     ✅     │     ✅     │     ❌     │     ❌     │     ✅     │     ✅     │
│  📋 Audit       │     ✅     │     ✅     │     ❌     │     ❌     │     ❌     │     ❌     │
├─────────────────┼────────────┼────────────┼────────────┼────────────┼────────────┼────────────┤
│  Trust Minimo   │     40     │     40     │     40     │     40     │     40     │     40     │
│  per Stats      │            │            │            │            │            │            │
└─────────────────┴────────────┴────────────┴────────────┴────────────┴────────────┴────────────┘
```

### Permessi per Azione

| Ruolo | Read | Write | Delete | Admin |
|-------|------|-------|--------|-------|
| `ceo` | ✅ | ✅ | ✅ | ✅ |
| `cto` | ✅ | ✅ | ✅ | ✅ |
| `hr_manager` | ✅ | ✅ | ❌ | ❌ |
| `sales_manager` | ✅ | ✅ | ❌ | ❌ |
| `developer` | ✅ | ❌ | ❌ | ❌ |
| `analyst` | ✅ | ❌ | ❌ | ❌ |

---

## 🧪 Scenari di Test

### Scenario 1: Development Host (Trusted)

| Proprietà | Valore |
|-----------|--------|
| **URL** | http://localhost:5700 |
| **IP** | 172.28.5.10 |
| **Network** | Development (172.28.5.0/24) |
| **Context Bonus** | +25 |
| **Trust Score (CEO)** | ~93 |
| **Trust Score (Dev)** | ~84 |
| **Accesso** | ✅ Full Access |

### Scenario 2: Production Host (Trusted)

| Proprietà | Valore |
|-----------|--------|
| **URL** | http://localhost:5800 |
| **IP** | 172.28.4.10 |
| **Network** | Production (172.28.4.0/24) |
| **Context Bonus** | +30 |
| **Trust Score (CEO)** | ~98 |
| **Trust Score (Dev)** | ~88 |
| **Accesso** | ✅ Full Access |

### Scenario 3: External Allowed (Whitelist)

| Proprietà | Valore |
|-----------|--------|
| **URL** | http://localhost:5900 |
| **IP** | 172.28.1.100 |
| **Network** | External (Whitelist) |
| **Context Penalty** | -15 |
| **Trust Score (CEO)** | ~78 |
| **Trust Score (Dev)** | ~65 |
| **Accesso** | ⚠️ Standard/Limited |

### Scenario 4: External Blocked (Blacklist)

| Proprietà | Valore |
|-----------|--------|
| **URL** | http://localhost:5901 |
| **IP** | 172.28.1.200 |
| **Network** | External (Blacklist) |
| **Context Score** | 0 |
| **Trust Score** | ~9 |
| **Accesso** | ❌ Access Denied |

### Scenario 5: Malicious Host (Isolated)

| Proprietà | Valore |
|-----------|--------|
| **URL** | http://localhost:5902 |
| **IP** | 172.28.1.250 |
| **Network** | Isolated |
| **Status** | 🚫 Completamente Bloccato a L3 |

---

## 🚀 Guida all'Installazione

### Prerequisiti

- **Docker** ≥ 20.10
- **Docker Compose** ≥ 2.0
- **RAM** ≥ 8 GB (Splunk richiede risorse)
- **Porte libere**: 3128, 5000, 5432, 5700-5902, 8000, 8080, 8088, 8180, 8888, 9090

### Installazione

```bash
# 1. Clona il repository
git clone https://github.com/your-repo/techcorp-zerotrust.git
cd techcorp-zerotrust

# 2. Build dei container
docker-compose build

# 3. Avvia l'infrastruttura
docker-compose up -d

# 4. Attendi che tutti i servizi siano pronti (2-3 minuti)
# Splunk impiega più tempo per inizializzare

# 5. Verifica lo stato
docker-compose ps
```

### Verifica Servizi

```bash
# PDP - Policy Decision Point
curl http://localhost:5000/health
# Output: {"status": "healthy", "service": "PDP", ...}

# PEP - Policy Enforcement Point
curl http://localhost:8080/health
# Output: {"status": "healthy", "service": "PEP", ...}

# Snort IDS
curl http://localhost:9090/health
# Output: {"status": "healthy", "service": "Snort-IDS", ...}

# Splunk (potrebbe richiedere login)
curl -I http://localhost:8000
# Output: HTTP/1.1 200 OK
```

---

## 🧪 Test e Validazione

### Test Automatizzati

```bash
# Esegui la suite di test completa
./test_scenarios.sh
```

### Test Manuali

#### Test 1: Trust Score CEO da Production

```bash
curl -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{
    "username": "m.rossi",
    "source_ip": "172.28.4.10",
    "roles": ["ceo"]
  }'
```

**Output atteso:**
```json
{
  "username": "m.rossi",
  "trust_score": 93.5,
  "components": {
    "base_trust": 100,
    "history_score": 70,
    "anomaly_score": 100,
    "context_score": 100
  }
}
```

#### Test 2: Trust Score Developer da External

```bash
curl -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{
    "username": "p.ferrari",
    "source_ip": "172.28.1.100",
    "roles": ["developer"]
  }'
```

**Output atteso:** Trust Score ~65

#### Test 3: IP Blacklisted

```bash
curl -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "source_ip": "172.28.1.200",
    "roles": []
  }'
```

**Output atteso:** Trust Score < 20

#### Test 4: SQL Injection Detection

```bash
curl -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type": "sqli"}'
```

**Output atteso:**
```json
{
  "test_type": "sqli",
  "detected": true,
  "alerts": [
    {"rule_id": "SQLI-001", "rule_name": "SQL Injection Attempt - UNION", ...},
    {"rule_id": "SQLI-002", "rule_name": "SQL Injection Attempt - Boolean", ...}
  ]
}
```

#### Test 5: XSS Detection

```bash
curl -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type": "xss"}'
```

#### Test 6: Policy Evaluation - Allow

```bash
curl -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"username": "m.rossi", "roles": ["ceo"]},
    "device": {"ip": "172.28.4.10", "network": "production"},
    "resource": {"type": "employees", "action": "read"},
    "context": {}
  }'
```

**Output atteso:** `"decision": "allow"`

#### Test 7: Policy Evaluation - Deny

```bash
curl -X POST http://localhost:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"username": "attacker", "roles": []},
    "device": {"ip": "172.28.1.200", "network": "external"},
    "resource": {"type": "employees", "action": "read"},
    "context": {}
  }'
```

**Output atteso:** `"decision": "deny"`

---

## 📊 Monitoraggio su Splunk

### Accesso

| Proprietà | Valore |
|-----------|--------|
| **URL** | http://localhost:8000 |
| **Username** | admin |
| **Password** | TechCorp2024! |

### Query di Esempio

```spl
# Tutti gli eventi nell'ultimo giorno
index=zerotrust earliest=-24h | stats count by sourcetype

# Trust Score medio per utente
index=zerotrust sourcetype=pdp_decision 
| stats avg(trust_score) as avg_trust by username 
| sort - avg_trust

# Attacchi bloccati da Snort
index=zerotrust sourcetype=snort_ids action=block 
| timechart count by rule_name

# Top 10 IP con più alert
index=zerotrust sourcetype=snort_ids 
| stats count by source_ip 
| sort - count 
| head 10

# Accessi negati per motivo
index=zerotrust decision=deny 
| stats count by reason 
| sort - count
```

---

## 🔧 Troubleshooting

### Rebuild Completo

```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### Log dei Servizi

```bash
# PDP logs
docker-compose logs -f pdp

# PEP logs
docker-compose logs -f pep

# Snort IDS logs
docker-compose logs -f snort-ids

# Splunk logs
docker-compose logs -f splunk
```

### Problemi Comuni

| Problema | Soluzione |
|----------|-----------|
| Splunk non parte | Verificare RAM (min 4GB), attendere 2-3 minuti |
| PDP non raggiunge SIEM | Verificare che Splunk sia up: `curl http://localhost:8000` |
| Trust Score sempre 70 | SIEM non raggiungibile, history_score usa default |
| Keycloak login fallisce | Verificare porta 8180, attendere startup |

---

## 📚 Riferimenti

### Standard e Best Practices

- [NIST SP 800-207 - Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
- [Google BeyondCorp](https://cloud.google.com/beyondcorp)

### Documentazione Tool

- [Snort User Manual](https://www.snort.org/documents)
- [Splunk Documentation](https://docs.splunk.com/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

---

## 📄 Struttura del Progetto

```
techcorp-zerotrust/
│
├── 📁 database/
│   └── init.sql                    # Schema PostgreSQL + dati test
│
├── 📁 pdp/
│   ├── pdp.py                      # Policy Decision Point (Flask)
│   ├── policies.json               # Policy statiche
│   ├── requirements.txt            # Dependencies Python
│   └── Dockerfile
│
├── 📁 pep/
│   ├── pep.js                      # Policy Enforcement Point (Express)
│   ├── package.json                # Dependencies Node.js
│   └── Dockerfile
│
├── 📁 snort-ids/
│   ├── snort_ids.py                # IDS Simulator (Flask)
│   ├── rules/
│   │   └── local.rules             # Snort rules file
│   └── Dockerfile
│
├── 📁 iptables-firewall/
│   ├── firewall.py                 # L3 Firewall Simulator
│   └── Dockerfile
│
├── 📁 squid-proxy/
│   ├── squid.py                    # L7 Proxy Simulator
│   └── Dockerfile
│
├── 📁 identity-provider/
│   └── realm-export.json           # Keycloak realm config
│
├── 📁 siem-splunk/
│   └── inputs.conf                 # Splunk inputs config
│
├── 📁 scenarios/
│   ├── dev-host/                   # Development workstation
│   ├── prod-host/                  # Production workstation
│   ├── external-allowed/           # External whitelist host
│   ├── external-blocked/           # External blacklist host
│   └── malicious-host/             # Attacker simulation
│
├── 📁 external-servers/
│   ├── allowed-server/             # Partner autorizzato
│   └── blocked-server/             # Server bloccato
│
├── docker-compose.yaml             # Orchestrazione container
├── test_scenarios.sh               # Script test automatizzati
└── README.md                       # Questa documentazione
```

---

**Versione:** 2.0  
**Data:** Gennaio 2025  
**Gruppo:** Sicurezza Avanzata - Università Politecnica delle Marche

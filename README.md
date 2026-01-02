# 🧪 TechCorp Zero Trust Architecture

## 📚 Progetto di Sicurezza Avanzata
**Università Politecnica delle Marche** - Corso di Laurea Magistrale in Ingegneria Informatica  
**Docente:** Prof. Luca Spalazzi | **A.A. 2024/2025**

---

## 🚀 Quick Start

```bash
docker-compose build
docker-compose up -d
# Attendere 2-3 minuti per l'avvio completo
```

### Verifica Servizi
```bash
curl http://localhost:5000/health   # PDP
curl http://localhost:8080/health   # PEP
curl http://localhost:9090/health   # Snort IDS
```

---

## 🏢 Descrizione del Progetto

TechCorp è un'azienda tecnologica che ha implementato un'architettura **Zero Trust** per proteggere le proprie risorse aziendali. Il sistema implementa il principio "**Never Trust, Always Verify**" attraverso:

- **Autenticazione continua** tramite Keycloak (OAuth2/OIDC)
- **Autorizzazione dinamica** basata su Trust Score calcolato in tempo reale
- **Intrusion Detection** con Snort IDS per rilevare attacchi
- **Firewall multi-livello** (iptables + Squid Proxy)
- **Logging centralizzato** su Splunk SIEM

### Componenti Implementati

| Componente | Tecnologia | Porta | Funzione |
|------------|------------|-------|----------|
| 🔐 **PDP** | Python/Flask | 5000 | Policy Decision Point - Calcola Trust Score |
| 🚪 **PEP** | Node.js | 8080 | Policy Enforcement Point - Gateway accesso |
| 🛡️ **Snort IDS** | Python | 9090 | Intrusion Detection System |
| 🔥 **iptables** | Python | 8888 | Firewall a livello di rete (L3) |
| 🦑 **Squid** | Python | 3128 | Firewall applicativo (L7) |
| 📊 **Splunk** | Docker | 8000 | SIEM - Logging e analisi |
| 🔑 **Keycloak** | Docker | 8180 | Identity Provider |
| 🗄️ **PostgreSQL** | Docker | 5432 | Database aziendale |

---

## 👥 Utenti Aziendali TechCorp

### Organigramma e Ruoli

| Username | Password | Ruolo | Dipartimento | Descrizione |
|----------|----------|-------|--------------|-------------|
| **m.rossi** | CEO2024! | `ceo` | Direzione | CEO - Accesso completo a tutte le risorse |
| **l.bianchi** | CTO2024! | `cto` | IT | CTO - Accesso completo + audit logs |
| **g.verdi** | HR2024! | `hr_manager` | HR | HR Manager - Gestione dipendenti |
| **a.romano** | Sales2024! | `sales_manager` | Sales | Sales Manager - Clienti e ordini |
| **p.ferrari** | Dev2024! | `developer` | IT | Developer - Progetti e codice |
| **e.colombo** | Analyst2024! | `analyst` | Finance | Analyst - Report e statistiche |

### Permessi per Ruolo

| Ruolo | 📊 Stats | 👥 Employees | 🏢 Customers | 📦 Orders | 💼 Projects | 📋 Audit |
|-------|----------|--------------|--------------|-----------|-------------|----------|
| `ceo` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cto` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `hr_manager` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `sales_manager` | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| `developer` | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| `analyst` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |

### Trust Score Base per Ruolo

| Ruolo | Trust Base | Motivazione |
|-------|------------|-------------|
| `ceo` | 100 | Massimo livello di fiducia |
| `cto` | 95 | Accesso tecnico privilegiato |
| `hr_manager` | 85 | Dati sensibili dipendenti |
| `sales_manager` | 80 | Dati clienti e commerciali |
| `developer` | 75 | Accesso al codice sorgente |
| `analyst` | 70 | Accesso in sola lettura |

---

## 🖥️ Scenari di Test - Host

### Scenario 1: Dev Host (Trusted)
- **URL:** http://localhost:5700
- **IP:** 172.28.5.10
- **Rete:** Development Network
- **Trust Score:** ~84
- **Accesso:** ✅ Full Access

### Scenario 2: Prod Host (Trusted)
- **URL:** http://localhost:5800
- **IP:** 172.28.4.10
- **Rete:** Production Network
- **Trust Score:** ~93
- **Accesso:** ✅ Full Access

### Scenario 3: External Allowed (Whitelisted)
- **URL:** http://localhost:5900
- **IP:** 172.28.1.100
- **Rete:** External Network (Whitelist)
- **Trust Score:** ~78
- **Accesso:** ⚠️ Limited Access

### Scenario 4: External Blocked (Blacklisted)
- **URL:** http://localhost:5901
- **IP:** 172.28.1.200
- **Rete:** External Network (Blacklist)
- **Trust Score:** ~9
- **Accesso:** ❌ Access Denied

### Scenario 5: Malicious Host (Isolated)
- **URL:** http://localhost:5902
- **IP:** 172.28.1.250
- **Rete:** Isolato
- **Accesso:** 🚫 Completamente Bloccato

---

## 🛡️ Scenari di Test - Snort IDS

Il sistema **Snort IDS** analizza ogni richiesta in tempo reale per rilevare pattern di attacco.

### 📍 Endpoint IDS
- **Health:** http://localhost:9090/health
- **Regole:** http://localhost:9090/rules
- **Statistiche:** http://localhost:9090/stats
- **Test Attacchi:** http://localhost:9090/test-attack

### Test 1: SQL Injection Detection
```bash
curl -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type": "sqli"}'
```
**Risultato atteso:** Alert con regole `SQLI-001`, `SQLI-002`

### Test 2: XSS (Cross-Site Scripting)
```bash
curl -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type": "xss"}'
```
**Risultato atteso:** Alert con regola `XSS-001`

### Test 3: Path Traversal
```bash
curl -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type": "traversal"}'
```
**Risultato atteso:** Alert con regole `TRAV-001`, `TRAV-002`

### Test 4: Command Injection
```bash
curl -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type": "cmdi"}'
```
**Risultato atteso:** Alert con regola `CMD-001`

### Test 5: Scanner Detection
```bash
curl -X POST http://localhost:9090/test-attack \
  -H "Content-Type: application/json" \
  -d '{"type": "scan"}'
```
**Risultato atteso:** Alert con regola `SCAN-002` (Nikto scanner)

### Regole Snort Implementate

| ID | Nome | Severità | Categoria |
|----|------|----------|-----------|
| `SQLI-001` | SQL Injection - UNION | 🔴 Critical | Injection |
| `SQLI-002` | SQL Injection - Boolean | 🔴 Critical | Injection |
| `SQLI-003` | SQL Injection - Time-based | 🔴 Critical | Injection |
| `XSS-001` | XSS - Script Tag | 🟠 High | XSS |
| `XSS-002` | XSS - Event Handler | 🟠 High | XSS |
| `TRAV-001` | Directory Traversal | 🟠 High | Traversal |
| `TRAV-002` | Sensitive File Access | 🔴 Critical | Traversal |
| `CMD-001` | Command Injection | 🔴 Critical | Injection |
| `CMD-002` | Shell Metacharacter | 🟠 High | Injection |
| `SCAN-001` | Port Scan Detection | 🟡 Medium | Reconnaissance |
| `SCAN-002` | Vulnerability Scanner | 🟠 High | Reconnaissance |
| `UA-001` | Malicious Bot | 🟡 Medium | Bot |
| `BRUTE-001` | Login Brute Force | 🟠 High | Brute Force |

### Test da Browser (Simulazione Attacco)

1. Vai su http://localhost:5700 (Dev Host)
2. Effettua login con un utente
3. Nella barra degli indirizzi del browser aziendale, inserisci:
   ```
   /api/test?id=1' OR '1'='1
   ```
4. **Risultato atteso:** Richiesta bloccata da Snort IDS

---

## 🔐 Scenari di Test - Autenticazione e Trust Score

### Test 1: CEO da Production Network
```bash
curl -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{
    "username": "m.rossi",
    "source_ip": "172.28.4.10",
    "roles": ["ceo"]
  }'
```
**Trust Score atteso:** ~93-100 ✅

### Test 2: Developer da Development Network
```bash
curl -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{
    "username": "p.ferrari",
    "source_ip": "172.28.5.10",
    "roles": ["developer"]
  }'
```
**Trust Score atteso:** ~80-85 ✅

### Test 3: HR Manager da External (Whitelisted)
```bash
curl -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{
    "username": "g.verdi",
    "source_ip": "172.28.1.100",
    "roles": ["hr_manager"]
  }'
```
**Trust Score atteso:** ~60-70 ⚠️

### Test 4: Utente da IP Blacklisted
```bash
curl -X POST http://localhost:5000/trust-score \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "source_ip": "172.28.1.200",
    "roles": []
  }'
```
**Trust Score atteso:** <20 ❌ (Blacklisted)

---

## 🌐 Browser Aziendale - Test Navigazione

Ogni workstation include un **browser aziendale protetto** dalla Zero Trust Architecture con Squid Proxy.

### Accesso al Browser
1. Vai su http://localhost:5700 (dev-host) o http://localhost:5800 (prod-host)
2. Clicca sulla card "🌐 External Browser" nella homepage
3. Oppure dalla Dashboard, clicca "🌐 External Browser" nella navbar

### Partner Autorizzati (Whitelist)

| Sito | URL | Descrizione |
|------|-----|-------------|
| 🚚 **Logistica Italia S.r.l.** | www.logisticaitalia.com | Partner logistico per spedizioni |
| ☁️ **CloudServizi.it** | www.cloudservizi.it | Provider cloud enterprise |

### Siti Bloccati (Blacklist)

| Sito | URL | Motivo Blocco |
|------|-----|---------------|
| 🦠 Malware Download | www.malware-download.net | Distribuzione malware |
| 🎣 Phishing Site | www.phishing-site.com | Tentativo phishing |
| ⚠️ Hacker Tools | www.hacker-tools.org | Strumenti hacking |

### Test Squid Proxy

**Test 1:** Accesso a Partner Autorizzato
1. Vai al browser aziendale → Clicca "Logistica Italia"
2. ✅ **Risultato:** Pagina partner visibile

**Test 2:** Accesso a Sito Bloccato
1. Vai al browser aziendale → Clicca "Malware Download"
2. ❌ **Risultato:** Pagina "Accesso Bloccato" dal firewall

---

## 📊 Calcolo Trust Score

### Formula
```
Trust Score = (Base Trust × 0.30) + (History Score × 0.25) + 
              (Anomaly Score × 0.25) + (Context Score × 0.20)
```

### Componenti

| Componente | Peso | Descrizione |
|------------|------|-------------|
| **Base Trust** | 30% | Dal ruolo utente (50-100) |
| **History Score** | 25% | Storico dal SIEM (successi/fallimenti) |
| **Anomaly Score** | 25% | Eventi sicurezza recenti (0-100) |
| **Context Score** | 20% | Rete, orario, dispositivo |

### Context Score per Rete

| Rete | IP Range | Bonus/Malus |
|------|----------|-------------|
| Production | 172.28.4.0/24 | +30 |
| Development | 172.28.5.0/24 | +25 |
| Internal | 172.28.2.0/24 | +20 |
| DMZ | 172.28.3.0/24 | +15 |
| External (Whitelist) | 172.28.1.100 | -15 |
| External (Unknown) | 172.28.1.x | -40 |
| Blacklisted | 172.28.1.200/250 | =0 |

### Soglie di Accesso

| Trust Score | Livello | Azione |
|-------------|---------|--------|
| ≥ 80 | 🟢 Full Access | Accesso completo |
| 60-79 | 🟡 Standard Access | Accesso standard |
| 40-59 | 🟠 Limited Access | Accesso limitato |
| < 40 | 🔴 Denied | Accesso negato |

---

## 📊 Riepilogo Trust Score per Host

| Host | IP | Context Score | Trust Score (CEO) | Trust Score (Dev) |
|------|-----|---------------|-------------------|-------------------|
| prod-host | 172.28.4.10 | 100 | ~93 | ~84 |
| dev-host | 172.28.5.10 | 95 | ~91 | ~82 |
| external-allowed | 172.28.1.100 | 55 | ~78 | ~65 |
| external-blocked | 172.28.1.200 | 0 | ~9 | ~9 |
| malicious-host | 172.28.1.250 | N/A | BLOCKED | BLOCKED |

---

## 📈 Monitoraggio su Splunk

### Accesso
- **URL:** http://localhost:8000
- **Username:** admin
- **Password:** TechCorp2024!

### Query Utili

```spl
# Tutti gli eventi Zero Trust
index=zerotrust | stats count by sourcetype

# Decisioni PDP
index=zerotrust sourcetype=pdp_decision | table timestamp username decision trust_score

# Alert Snort IDS
index=zerotrust sourcetype=snort_ids | table timestamp rule_name severity source_ip

# Accessi negati
index=zerotrust decision=deny | stats count by username, reason
```

---

## 🗂️ Struttura del Progetto

```
techcorp-zerotrust/
├── 📁 database/
│   └── init.sql                 # Schema e dati iniziali
├── 📁 pdp/
│   ├── pdp.py                   # Policy Decision Point
│   └── policies.json            # Policy statiche
├── 📁 pep/
│   └── pep.js                   # Policy Enforcement Point
├── 📁 snort-ids/
│   ├── snort_ids.py             # Intrusion Detection System
│   └── rules/local.rules        # Regole custom Snort
├── 📁 iptables-firewall/
│   └── firewall.py              # Firewall L3
├── 📁 squid-proxy/
│   └── squid.py                 # Firewall L7
├── 📁 identity-provider/
│   └── realm-export.json        # Config Keycloak
├── 📁 scenarios/
│   ├── dev-host/                # Host development
│   ├── prod-host/               # Host production
│   ├── external-allowed/        # Host esterno autorizzato
│   ├── external-blocked/        # Host esterno bloccato
│   └── malicious-host/          # Host malevolo
├── docker-compose.yaml
├── test_scenarios.sh            # Script test automatizzati
└── README.md
```

---

## 🗺️ Architettura di Rete

```
                           ┌─────────────────────────────────────┐
                           │         EXTERNAL NETWORK            │
                           │           172.28.1.0/24             │
                           │  ┌─────────┐ ┌─────────┐ ┌────────┐│
                           │  │Allowed  │ │Blocked  │ │Malicious│
                           │  │.100     │ │.200     │ │.250    ││
                           │  └────┬────┘ └────┬────┘ └───┬────┘│
                           └───────┼───────────┼──────────┼─────┘
                                   │           │          │
┌──────────────────────────────────┼───────────┼──────────┼──────┐
│                           DMZ NETWORK                          │
│                           172.28.3.0/24                        │
│    ┌──────────┐     ┌──────────┐     ┌──────────┐              │
│    │   PEP    │     │ Keycloak │     │Snort IDS │              │
│    │  .10     │     │   .20    │     │   .2     │              │
│    └────┬─────┘     └──────────┘     └──────────┘              │
└─────────┼──────────────────────────────────────────────────────┘
          │
┌─────────┼──────────────────────────────────────────────────────┐
│         │              INTERNAL NETWORK                        │
│         │              172.28.2.0/24                           │
│    ┌────┴─────┐     ┌──────────┐     ┌──────────┐              │
│    │   PDP    │     │  Splunk  │     │PostgreSQL│              │
│    │   .20    │     │   .10    │     │   .40    │              │
│    └──────────┘     └──────────┘     └──────────┘              │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────┐    ┌────────────────────────┐
│   PRODUCTION NETWORK   │    │  DEVELOPMENT NETWORK   │
│     172.28.4.0/24      │    │    172.28.5.0/24       │
│   ┌──────────────┐     │    │   ┌──────────────┐     │
│   │  Prod Host   │     │    │   │  Dev Host    │     │
│   │    .10       │     │    │   │    .10       │     │
│   │ Trust: +30   │     │    │   │ Trust: +25   │     │
│   └──────────────┘     │    │   └──────────────┘     │
└────────────────────────┘    └────────────────────────┘
```

---

## 🛠️ Troubleshooting

### Rebuild Completo
```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### Verifica Log Specifici
```bash
# Log PDP (decisioni)
docker-compose logs pdp | grep "trust"

# Log PEP (richieste)
docker-compose logs pep | grep "IP Detection"

# Log Snort IDS (alert)
docker-compose logs snort-ids | grep "alert"

# Log Splunk
docker-compose logs splunk
```

### Test Connettività
```bash
# Health checks
curl http://localhost:5000/health   # PDP
curl http://localhost:8080/health   # PEP
curl http://localhost:9090/health   # Snort IDS
curl http://localhost:9090/stats    # IDS Statistics
```

---

## 📚 Riferimenti

- [NIST SP 800-207 - Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
- [Snort User Manual](https://www.snort.org/documents)
- [Splunk Documentation](https://docs.splunk.com/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)

---

**Versione:** 1.0 | **Data:** Gennaio 2025 | **Gruppo:** Sicurezza Avanzata UNIVPM

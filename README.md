<div align="center">

# 🛡️ TechCorp Zero Trust Architecture

![Zero Trust](https://img.shields.io/badge/Security-Zero%20Trust-blue?style=for-the-badge&logo=shield)
![NIST](https://img.shields.io/badge/Standard-NIST%20SP%20800--207-green?style=for-the-badge)
![Docker](https://img.shields.io/badge/Container-Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)

### 🔐 Progetto di Sicurezza delle Reti
**Implementazione di un'Architettura Zero Trust con Trust Score Dinamico**

[📖 Documentazione](#-indice) • [🚀 Quick Start](#-appendice-a-guida-allinstallazione) • [🧪 Testing](#6--testing-e-validazione) • [📊 Dashboard](#appendice-d-query-splunk-utili)

</div>

---

## 📋 Abstract

Il presente progetto implementa un'architettura **Zero Trust** completa per l'azienda fittizia TechCorp, seguendo le linee guida dello standard **NIST SP 800-207**. Il sistema realizza il paradigma *"Never Trust, Always Verify"* attraverso l'integrazione di componenti fondamentali: un **Policy Decision Point (PDP)** che calcola dinamicamente un Trust Score basato su quattro fattori (ruolo utente, storico comportamentale, anomalie di sicurezza, contesto della richiesta), un **Policy Enforcement Point (PEP)** come gateway applicativo, un sistema di **Intrusion Detection** basato su Snort con 36 regole personalizzate, e un firewall multi-livello che opera sia a Layer 3 (iptables) che a Layer 7 (Squid).

L'architettura è stata progettata con un approccio **Defense in Depth**, dove ogni richiesta attraversa multiple fasi di verifica prima di accedere alle risorse protette. Il sistema integra **Splunk** come SIEM per il logging centralizzato e l'analisi storica, **Keycloak** per l'identity management con autenticazione JWT, e **PostgreSQL** come database aziendale contenente dati sensibili.

La validazione è stata effettuata attraverso 15 scenari di test che coprono casi d'uso legittimi, tentativi di accesso non autorizzato, e simulazioni di attacchi (SQL Injection, XSS, Path Traversal). I risultati dimostrano l'efficacia dell'architettura nel garantire il principio del minimo privilegio e nel rilevare comportamenti anomali in tempo reale.

> 🏷️ **Parole chiave:** `Zero Trust` `Network Security` `Access Control` `Trust Score` `SIEM` `IDS` `Policy-Based Access Control` `NIST 800-207`

---

## 📑 Indice

| # | Sezione | Descrizione |
|:-:|---------|-------------|
| 1️⃣ | [Introduzione](#1--introduzione) | Contesto, motivazioni e obiettivi |
| 2️⃣ | [Background Teorico](#2--background-teorico) | Paradigma Zero Trust e stato dell'arte |
| 3️⃣ | [Analisi dei Requisiti](#3--analisi-dei-requisiti) | Requisiti funzionali e non funzionali |
| 4️⃣ | [Progettazione](#4--progettazione) | Architettura e scelte progettuali |
| 5️⃣ | [Implementazione](#5--implementazione) | Dettagli implementativi |
| 6️⃣ | [Testing e Validazione](#6--testing-e-validazione) | Scenari di test e risultati |
| 7️⃣ | [Analisi di Sicurezza](#7--analisi-di-sicurezza) | Valutazione sicurezza |
| 8️⃣ | [Discussione](#8--discussione) | Risultati e limitazioni |
| 9️⃣ | [Conclusioni](#9--conclusioni) | Conclusioni e sviluppi futuri |
| 🔟 | [Riferimenti](#10--riferimenti-bibliografici) | Bibliografia |
| 📎 | [Appendici](#-appendici) | Guide e risorse aggiuntive |

---

## 1. 🎯 Introduzione

### 1.1 📌 Contesto e Motivazioni

Le architetture di sicurezza tradizionali basate sul concetto di "perimetro sicuro" (*castle-and-moat*) si sono dimostrate inadeguate di fronte all'evoluzione delle minacce informatiche moderne. L'aumento del lavoro remoto, l'adozione di servizi cloud, e la crescente sofisticazione degli attacchi hanno evidenziato i limiti di un approccio che considera "trusted" tutto il traffico interno alla rete aziendale.

Il modello **Zero Trust**, formalizzato da Forrester Research nel 2010 [3] e successivamente standardizzato dal NIST [1], propone un cambio di paradigma radicale: *nessuna entità è considerata affidabile a priori*, indipendentemente dalla sua posizione nella rete.

### 1.2 🎯 Obiettivi del Progetto

Il presente lavoro si propone di:

| # | Obiettivo | Descrizione |
|:-:|-----------|-------------|
| 🏗️ | **Architettura ZT** | Implementare un'architettura Zero Trust funzionante che dimostri i principi teorici in un ambiente simulato ma realistico |
| 📊 | **Trust Score** | Realizzare un sistema di Trust Score dinamico che valuti ogni richiesta basandosi su molteplici fattori contestuali |
| 🔧 | **Integrazione** | Integrare tecnologie di sicurezza enterprise (Snort, Splunk, Squid, iptables) in un'architettura coesa |
| ✅ | **Validazione** | Validare l'efficacia attraverso scenari di test che simulino sia utilizzi legittimi che tentativi di attacco |

### 1.3 📖 Struttura del Documento

Il documento è organizzato come segue: la Sezione 2 presenta il background teorico e lo stato dell'arte; la Sezione 3 dettaglia i requisiti del progetto; la Sezione 4 descrive le scelte progettuali; la Sezione 5 illustra l'implementazione; la Sezione 6 presenta i test effettuati; la Sezione 7 analizza gli aspetti di sicurezza; la Sezione 8 discute risultati e limitazioni; la Sezione 9 conclude il lavoro.

---

## 2. 📚 Background Teorico

### 2.1 🔐 Il Paradigma Zero Trust

L'architettura Zero Trust si fonda su tre principi fondamentali definiti dal NIST SP 800-207 [1]:

| Principio | Descrizione | Implementazione nel Progetto |
|:---------:|-------------|------------------------------|
| ✅ **Verifica Esplicita** | Ogni richiesta deve essere autenticata e autorizzata sulla base di tutti i dati disponibili | PEP verifica token JWT + PDP calcola Trust Score |
| 🔒 **Minimo Privilegio** | L'accesso è limitato al minimo necessario, con protezione just-in-time e just-enough | ACL per ruolo + soglie Trust Score per risorsa |
| ⚠️ **Assume Breach** | Il sistema è progettato assumendo che la rete sia già compromessa | IDS inline, logging completo, micro-segmentazione |

### 2.2 🔄 Differenza con l'Approccio Tradizionale

```
┌─────────────────────────────────────────────────────────────────────────┐
│              ❌ APPROCCIO TRADIZIONALE (Perimetrale)                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│    🌐 INTERNET ──── [🧱 Firewall] ──── RETE INTERNA (tutti trusted)    │
│                                                                         │
│    ✗ Una volta dentro, accesso libero                                  │
│    ✗ Movimento laterale possibile                                      │
│    ✗ Insider threat non gestito                                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              ✅ APPROCCIO ZERO TRUST (Questo Progetto)                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│    📨 RICHIESTA ──── [🚪 PEP] ──── [🔍 IDS] ──── [🧠 PDP] ──── 📦      │
│                          │          │           │                       │
│                          └──────────┴───────────┴──── [📊 SIEM]        │
│                                                                         │
│    ✓ Verifica continua ad ogni richiesta                               │
│    ✓ Trust Score dinamico basato su contesto                           │
│    ✓ Logging centralizzato per analisi                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.3 🌍 Stato dell'Arte

Le implementazioni Zero Trust più note in letteratura includono:

| Soluzione | Descrizione |
|-----------|-------------|
| 🔵 **Google BeyondCorp** [4] | Prima implementazione enterprise su larga scala, elimina completamente il concetto di VPN |
| 🟦 **Microsoft Zero Trust** | Integrato in Azure AD e Microsoft 365 |
| 🟢 **NIST ZTA** [1] | Framework di riferimento che definisce componenti e flussi standard |

Il presente progetto si basa sul modello NIST, implementando specificamente i componenti PDP (Policy Decision Point) e PEP (Policy Enforcement Point) descritti nello standard.

### 2.4 🧩 Componenti di un'Architettura Zero Trust

Secondo il NIST SP 800-207, i componenti fondamentali sono:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   🎛️ CONTROL PLANE                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐    │
│  │                        🧠 Policy Decision Point (PDP)                                   │    │
│  │                                                                                          │    │
│  │   • 📥 Riceve richiesta (s, d, n, o, r) dal PEP                                         │    │
│  │   • 📊 Interroga SIEM per history utente                                                │    │
│  │   • 🔢 Calcola Trust Score dinamico                                                     │    │
│  │   • 📋 Verifica policy (ACL, ruoli, soglie)                                             │    │
│  │   • ✅❌ Restituisce decisione: ALLOW / DENY                                            │    │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
                                              │
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    📡 DATA PLANE                                                 │
│  ┌───────────┐    Request     ┌─────────────────────────────┐    Decision    ┌───────────────┐  │
│  │  👤 User  │ ─────────────► │  🚪 Policy Enforcement Point │ ─────────────► │  📦 Resource  │  │
│  │           │   (s,d,n,o,r)  │            (PEP)             │    Applied     │               │  │
│  └───────────┘                └─────────────────────────────┘                └───────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

📖 Legenda:
  s = Subject (utente)       d = Device (dispositivo)      n = Network (rete di provenienza)
  o = Object (risorsa)       r = Request type (azione: read, write, delete)
```

---

## 3. 📋 Analisi dei Requisiti

### 3.1 ⚙️ Requisiti Funzionali

| ID | Requisito | Descrizione | Priorità |
|:--:|-----------|-------------|:--------:|
| 🧠 **RF01** | Policy Decision Point | Implementare un PDP che valuti le richieste di accesso | 🔴 Alta |
| 🚪 **RF02** | Policy Enforcement Point | Implementare un PEP come gateway per tutte le richieste | 🔴 Alta |
| 📊 **RF03** | Trust Score Dinamico | Calcolare un punteggio di fiducia basato su multiple variabili | 🔴 Alta |
| 🔍 **RF04** | Intrusion Detection | Integrare Snort per rilevamento di attacchi | 🔴 Alta |
| 🧱 **RF05** | Firewall Layer 3 | Implementare filtraggio IP con iptables | 🔴 Alta |
| 🌐 **RF06** | Firewall Layer 7 | Implementare filtraggio applicativo con Squid | 🔴 Alta |
| 📈 **RF07** | SIEM Integration | Integrare Splunk per logging e analisi storica | 🔴 Alta |
| 🔑 **RF08** | Identity Management | Gestire autenticazione con Keycloak | 🟡 Media |
| 🗄️ **RF09** | Database Aziendale | Proteggere dati sensibili in PostgreSQL | 🟡 Media |
| 🧪 **RF10** | Scenari di Test | Simulare accessi autorizzati e non autorizzati | 🟡 Media |

### 3.2 📐 Requisiti Non Funzionali

| ID | Requisito | Specifica | Target |
|:--:|-----------|-----------|:------:|
| 🐳 **RNF01** | Containerizzazione | Tutti i componenti devono essere containerizzati | Docker |
| 🔀 **RNF02** | Segmentazione | Le reti devono essere logicamente separate | 5 subnet |
| 📝 **RNF03** | Logging | Tutti gli eventi devono essere registrati | 100% |
| 📈 **RNF04** | Scalabilità | L'architettura deve supportare scaling orizzontale | ✅ |

---

## 4. 🏗️ Progettazione

> *Sezione dettagliata nel documento completo*

---

## 5. 💻 Implementazione

> *Sezione dettagliata nel documento completo*

---

## 6. 🧪 Testing e Validazione

> *Sezione dettagliata nel documento completo*

---

## 7. 🔒 Analisi di Sicurezza

> *Sezione dettagliata nel documento completo*

---

## 8. 💬 Discussione

> *Sezione dettagliata nel documento completo*

---

## 9. ✅ Conclusioni

> *Sezione dettagliata nel documento completo*

---

## 10. 📚 Riferimenti Bibliografici

### 📄 Standard e Paper Accademici

| # | Riferimento |
|:-:|-------------|
| 📘 [1] | S. Rose et al., "Zero Trust Architecture," *NIST Special Publication 800-207*, Aug. 2020 |
| 📘 [2] | J. Saltzer and M. Schroeder, "The Protection of Information in Computer Systems," *Proceedings of the IEEE*, vol. 63, no. 9, pp. 1278-1308, Sept. 1975 |
| 📘 [3] | J. Kindervag, "Build Security Into Your Network's DNA: The Zero Trust Network Architecture," *Forrester Research*, Nov. 2010 |
| 📘 [4] | R. Ward and B. Beyer, "BeyondCorp: A New Approach to Enterprise Security," *USENIX ;login:*, vol. 39, no. 6, pp. 6-11, Dec. 2014 |
| 📕 [5] | E. Gilman and D. Barth, *Zero Trust Networks: Building Secure Systems in Untrusted Networks*, O'Reilly Media, 2017 |
| 📘 [6] | A. Kerman et al., "Implementing a Zero Trust Architecture," *NIST Cybersecurity White Paper*, Oct. 2020 |
| 📘 [7] | M. Roesch, "Snort - Lightweight Intrusion Detection for Networks," *Proceedings of LISA '99*, pp. 229-238, 1999 |

### 📖 Documentazione Tecnica

| # | Risorsa | Link |
|:-:|---------|------|
| 🔍 [8] | Snort 3 User Manual | https://www.snort.org/documents |
| 📊 [9] | Splunk Enterprise Documentation | https://docs.splunk.com/ |
| 🔑 [10] | Keycloak Server Administration Guide | https://www.keycloak.org/documentation |
| 🐘 [11] | PostgreSQL 15 Documentation | https://www.postgresql.org/docs/ |

---

## 📎 Appendici

### 📦 Appendice A: Guida all'Installazione

#### ✅ Prerequisiti

| Componente | Versione | Note |
|------------|:--------:|------|
| 🐳 Docker Engine | 20.10+ | Richiesto |
| 🐙 Docker Compose | 2.0+ | Richiesto |
| 💾 RAM | 8GB+ | 16GB consigliati |
| 💿 Disco | 20GB+ | SSD consigliato |

#### 🚀 Installazione

```bash
# 1. 📥 Clone del repository
git clone <repository-url>
cd techcorp-zerotrust

# 2. 🏗️ Build e avvio
docker-compose up -d --build

# 3. ✅ Verifica servizi (attendere 2-3 minuti)
docker-compose ps

# 4. 🧪 Test rapido
curl http://localhost:5000/health  # 🧠 PDP
curl http://localhost:8080/health  # 🚪 PEP
```

#### 🔐 Credenziali di Accesso

| Servizio | URL | Username | Password |
|:--------:|-----|:--------:|----------|
| 📊 Splunk | http://localhost:8000 | `admin` | `TechCorp2024!` |
| 🔑 Keycloak | http://localhost:8180 | `admin` | `TechCorp2024!` |
| 🐘 PostgreSQL | localhost:5432 | `techcorp_user` | `TechCorp2024!` |

---

### 📂 Appendice B: Struttura del Progetto

```
techcorp-zerotrust/
│
├── 🗄️ database/
│   └── init.sql                    # Schema PostgreSQL + dati test
│
├── 🧠 pdp/
│   ├── pdp.py                      # Policy Decision Point
│   ├── policies.json               # Policy statiche
│   ├── requirements.txt
│   └── Dockerfile
│
├── 🚪 pep/
│   ├── pep.js                      # Policy Enforcement Point
│   ├── package.json
│   └── Dockerfile
│
├── 🔍 snort-ids/
│   ├── snort_api.py                # API wrapper Snort
│   ├── snort.conf                  # Configurazione Snort
│   ├── rules/
│   │   └── local.rules             # 36 regole custom
│   └── Dockerfile
│
├── 🧱 iptables-firewall/
│   ├── firewall_proxy.py           # Firewall L3
│   ├── entrypoint.sh
│   └── Dockerfile
│
├── 🌐 squid-proxy/
│   ├── squid.conf                  # Configurazione Squid
│   ├── blocked_domains.txt
│   └── Dockerfile
│
├── 🔑 identity-provider/
│   └── realm-export.json           # Configurazione Keycloak
│
├── 📊 siem-splunk/
│   ├── inputs.conf
│   └── indexes.conf
│
├── 🧪 scenarios/                    # Host di test
│   ├── dev-host/
│   ├── prod-host/
│   ├── external-allowed/
│   ├── external-blocked/
│   └── malicious-host/
│
├── 🎬 resources/                    # Video demo scenari di test
│   ├── Rete-Interna->DBMS.mp4
│   ├── Rete-Esterna->DBMS.mp4
│   └── Rete-Interna->Rete-Esterna.mp4
│
├── 🐙 docker-compose.yaml
├── 🧪 test_scenarios.sh
└── 📖 README.md
```

---

### 📖 Appendice C: Glossario

| Termine | Definizione |
|:-------:|-------------|
| 📋 **ACL** | Access Control List - Lista che definisce permessi di accesso |
| 🏰 **DMZ** | Demilitarized Zone - Rete intermedia tra interna ed esterna |
| 📡 **HEC** | HTTP Event Collector - Endpoint Splunk per ingest eventi |
| 🔍 **IDS** | Intrusion Detection System - Sistema di rilevamento intrusioni |
| 🎫 **JWT** | JSON Web Token - Standard per token di autenticazione |
| 🔐 **JWKS** | JSON Web Key Set - Set di chiavi pubbliche per verifica JWT |
| 🔑 **OIDC** | OpenID Connect - Protocollo di autenticazione basato su OAuth2 |
| 🧠 **PDP** | Policy Decision Point - Componente che decide su richieste di accesso |
| 🚪 **PEP** | Policy Enforcement Point - Componente che applica decisioni di accesso |
| 👥 **RBAC** | Role-Based Access Control - Controllo accessi basato su ruoli |
| 📊 **SIEM** | Security Information and Event Management - Sistema di gestione eventi sicurezza |
| 📈 **Trust Score** | Punteggio numerico (0-100) che rappresenta il livello di fiducia |

---

### 📊 Appendice D: Query Splunk Utili

```spl
# 📊 Dashboard: Tutti gli eventi Zero Trust
index=zerotrust | stats count by sourcetype

# 👤 Trust Score medio per utente
index=zerotrust sourcetype=pdp_decision 
| stats avg(trust_score) as avg_trust by username 
| sort - avg_trust

# ⚠️ Alert IDS per severità
index=zerotrust sourcetype=snort_ids 
| stats count by severity rule_name
| sort - count

# ❌ Accessi negati per motivo
index=zerotrust decision=deny 
| stats count by username reason
| sort - count

# 📈 Timeline attacchi rilevati
index=zerotrust sourcetype=snort_ids action=block
| timechart count by rule_name
```

---

<div align="center">

### 🛠️ Tecnologie Utilizzate

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat-square&logo=nodedotjs&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat-square&logo=splunk&logoColor=white)

---

*📄 Documento redatto per il corso di **ADVANCED CYBERSECURITY FOR IT***  
*📅 Versione 1.0 - Gennaio 2025*

---

**Made with ❤️ for Zero Trust Security**

</div>

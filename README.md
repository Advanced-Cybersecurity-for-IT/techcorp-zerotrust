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

### 4.1 Scelte Architetturali e Motivazioni

#### 4.1.1 Scelta delle Tecnologie

| Componente | Tecnologia | Motivazione | Alternative Considerate |
|------------|------------|-------------|------------------------|
| **PDP** | Python/Flask | Rapidità di sviluppo, librerie mature per calcoli statistici, facile integrazione con API REST | Go (scartato: curva di apprendimento), Java (scartato: overhead eccessivo) |
| **PEP** | Node.js/Express | Performance eccellente per I/O asincrono, ecosystem JWT maturo (jsonwebtoken, jwks-rsa) | Python (scartato: GIL limita concorrenza), Nginx+Lua (scartato: complessità) |
| **IDS** | Snort 3 | Standard de-facto per IDS open-source, regole personalizzabili, supporto PCAP | Suricata (equivalente ma meno documentato), Zeek (più orientato all'analisi) |
| **Firewall L3** | iptables | Nativo Linux, affidabile, ben documentato | nftables (più moderno ma meno supporto Docker) |
| **Firewall L7** | Squid | Maturo, ACL potenti, supporto proxy trasparente | HAProxy (meno funzionalità L7), Nginx (meno flessibile per ACL) |
| **SIEM** | Splunk | Leader di mercato, query language potente, HEC per ingest real-time | ELK Stack (scartato: complessità setup), Graylog (meno features) |
| **IdP** | Keycloak | Open-source, OIDC/OAuth2 completo, gestione ruoli integrata | Auth0 (SaaS, costi), Okta (SaaS, costi) |
| **Database** | PostgreSQL | Robusto, ACID compliant, schema enterprise-ready | MySQL (meno features), MongoDB (non relazionale) |

#### 4.1.2 Pattern Architetturali

**Scelta: Architettura a Microservizi**

*Motivazione:*
- **Isolamento**: Ogni componente opera in un container separato, applicando il principio Zero Trust anche all'infrastruttura
- **Scalabilità**: Possibilità di scalare indipendentemente i singoli componenti
- **Resilienza**: Failure di un componente non compromette l'intero sistema
- **Deployment**: Facilità di aggiornamento e rollback

*Alternativa scartata: Monolite*
- Viola il principio di segmentazione
- Single point of failure
- Difficoltà di scaling

### 4.2 Architettura del Sistema

```
                                    ┌──────────────────────────────────────────────────────────────┐
                                    │                         DBMS                                  │
                                    │                     (PostgreSQL)                              │
                                    │                     172.28.2.40                               │
                                    └──────────────────────────────────────────────────────────────┘
                                                              │
                                                              │ log
                                                              ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────────┐
│    Firewall      │  │    Firewall      │  │       IDS        │  │      Logging Service         │
│  Network Level   │  │ Application Level│  │     (Snort)      │  │        (Splunk)              │
│   (iptables)     │  │    (Squid)       │  │   172.28.2.5     │  │      172.28.2.10             │
│  172.28.1.254    │  │   172.28.3.5     │  │                  │  │                              │
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
│  │                                   172.28.2.20:5000                                       │    │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
                                              │
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       DATA PLANE                                                 │
│  ┌───────────┐                ┌─────────────────────────────┐                ┌───────────────┐  │
│  │   User    │ ─────────────► │  Policy Enforcement Point   │ ─────────────► │   Resource    │  │
│  │           │                │      172.28.3.10:8080       │                │               │  │
│  └───────────┘                └─────────────────────────────┘                └───────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Topologia di Rete

Il sistema è organizzato in **5 reti logicamente separate** per implementare il principio di micro-segmentazione:

| Rete | Subnet | VLAN | Funzione | Componenti |
|------|--------|------|----------|------------|
| **External** | 172.28.1.0/24 | 10 | Rete esterna (Internet simulato) | Host esterni, attaccanti simulati |
| **DMZ** | 172.28.3.0/24 | 30 | Zona demilitarizzata | Squid, PEP, Keycloak |
| **Internal** | 172.28.2.0/24 | 20 | Rete interna sicura | PDP, Splunk, PostgreSQL, Snort |
| **Production** | 172.28.4.0/24 | 40 | Rete di produzione | Host di produzione |
| **Development** | 172.28.5.0/24 | 50 | Rete di sviluppo | Host di sviluppo |

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              TOPOLOGIA DI RETE                                          │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│   EXTERNAL NET (172.28.1.0/24)                                                         │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│   │ ext-allowed │  │ ext-blocked │  │  malicious  │  │   Keycloak  │                  │
│   │  .100       │  │  .200 ✗     │  │  .250 ✗     │  │    .20      │                  │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────┘                  │
│          │                │                │                                           │
│          └────────────────┴────────────────┘                                           │
│                           │                                                            │
│                           ▼                                                            │
│              ┌────────────────────────┐                                               │
│              │  IPTABLES FIREWALL     │  ◄── Layer 3 filtering                        │
│              │     172.28.1.254       │                                               │
│              └───────────┬────────────┘                                               │
│                          │                                                            │
│   DMZ NET (172.28.3.0/24)│                                                            │
│              ┌───────────┴────────────┐                                               │
│              │    SQUID PROXY         │  ◄── Layer 7 filtering                        │
│              │     172.28.3.5         │                                               │
│              └───────────┬────────────┘                                               │
│                          │                                                            │
│              ┌───────────┴────────────┐                                               │
│              │        PEP             │  ◄── Policy Enforcement                       │
│              │    172.28.3.10         │                                               │
│              └───────────┬────────────┘                                               │
│                          │                                                            │
│   INTERNAL NET           │                                                            │
│   (172.28.2.0/24)        │                                                            │
│   ┌──────────┐  ┌────────┴───────┐  ┌──────────┐  ┌──────────┐                       │
│   │   PDP    │  │   Snort IDS    │  │  Splunk  │  │ Postgres │                       │
│   │   .20    │  │     .5         │  │   .10    │  │   .40    │                       │
│   └──────────┘  └────────────────┘  └──────────┘  └──────────┘                       │
│                                                                                       │
│   PROD NET (172.28.4.0/24)         DEV NET (172.28.5.0/24)                           │
│   ┌──────────┐                     ┌──────────┐                                      │
│   │prod-host │                     │ dev-host │                                      │
│   │   .10    │                     │   .10    │                                      │
│   └──────────┘                     └──────────┘                                      │
│                                                                                       │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.4 Flusso di una Richiesta

Il diagramma seguente illustra il flusso completo di una richiesta di accesso attraverso l'architettura:

```
  USER            FIREWALL L3      FIREWALL L7        IDS           PEP           PDP          SIEM        DATABASE
   │               (iptables)        (Squid)        (Snort)
   │                   │                │              │             │             │             │             │
   │ 1. HTTP Request   │                │              │             │             │             │             │
   │──────────────────►│                │              │             │             │             │             │
   │                   │                │              │             │             │             │             │
   │                   │ 2. IP Check    │              │             │             │             │             │
   │                   │ (Blacklist?)   │              │             │             │             │             │
   │                   │────────────────►              │             │             │             │             │
   │                   │      LOG──────────────────────────────────────────────────────────────►│             │
   │                   │                │              │             │             │             │             │
   │                   │                │ 3. L7 Check  │             │             │             │             │
   │                   │                │ (Domain/URL) │             │             │             │             │
   │                   │                │─────────────►│             │             │             │             │
   │                   │                │    LOG───────────────────────────────────────────────►│             │
   │                   │                │              │             │             │             │             │
   │                   │                │              │ 4. Deep     │             │             │             │
   │                   │                │              │ Packet      │             │             │             │
   │                   │                │              │ Inspection  │             │             │             │
   │                   │                │              │────────────►│             │             │             │
   │                   │                │              │   LOG───────────────────────────────────►             │
   │                   │                │              │             │             │             │             │
   │                   │                │              │             │ 5. Verify   │             │             │
   │                   │                │              │             │ JWT Token   │             │             │
   │                   │                │              │             │             │             │             │
   │                   │                │              │             │ 6. Policy   │             │             │
   │                   │                │              │             │ Request     │             │             │
   │                   │                │              │             │────────────►│             │             │
   │                   │                │              │             │             │ 7. Query    │             │
   │                   │                │              │             │             │ History     │             │
   │                   │                │              │             │             │────────────►│             │
   │                   │                │              │             │             │◄────────────│             │
   │                   │                │              │             │             │             │             │
   │                   │                │              │             │             │ 8. Calculate│             │
   │                   │                │              │             │             │ Trust Score │             │
   │                   │                │              │             │             │             │             │
   │                   │                │              │             │◄────────────│             │             │
   │                   │                │              │             │ 9. Decision │             │             │
   │                   │                │              │             │ (ALLOW/DENY)│             │             │
   │                   │                │              │             │             │             │             │
   │                   │                │              │             │ 10. If ALLOW│             │             │
   │                   │                │              │             │────────────────────────────────────────►│
   │                   │                │              │             │◄────────────────────────────────────────│
   │◄──────────────────────────────────────────────────────────────────────────────│             │             │
   │                                  11. Response                                  │             │             │
```


---

## 5. 💻 Implementazione


### 5.1 Trust Score: Algoritmo e Componenti

Il **Trust Score** è il cuore dell'architettura Zero Trust implementata. È un valore numerico (0-100) calcolato dinamicamente per ogni richiesta.

#### 5.1.1 Formula di Calcolo

```
Trust Score = (Base Trust × 0.30) + (History Score × 0.25) + 
              (Anomaly Score × 0.25) + (Context Score × 0.20)
```

#### 5.1.2 Componenti del Trust Score

**1. Base Trust (30%) - Derivato dal ruolo utente**

| Ruolo | Base Trust | Motivazione |
|-------|------------|-------------|
| `ceo` | 100 | Massimo livello di responsabilità e fiducia |
| `cto` | 95 | Accesso tecnico privilegiato |
| `hr_manager` | 85 | Gestisce dati sensibili dei dipendenti |
| `sales_manager` | 80 | Accesso a dati clienti e commerciali |
| `developer` | 75 | Accesso a codice e sistemi tecnici |
| `analyst` | 70 | Accesso in sola lettura |
| `default` | 50 | Utente non riconosciuto |

**2. History Score (25%) - Dal SIEM (Splunk)**

Calcolato interrogando lo storico dell'utente nelle ultime 24 ore:

```python
history_score = (successful_accesses / total_accesses) × 100
```

**3. Anomaly Score (25%) - Eventi di sicurezza recenti**

| Eventi di Sicurezza (ultima ora) | Anomaly Score |
|----------------------------------|---------------|
| > 10 eventi | 20 (alto rischio) |
| 6-10 eventi | 50 |
| 1-5 eventi | 70 |
| 0 eventi | 100 (nessuna anomalia) |

**4. Context Score (20%) - Fattori contestuali**

| Fattore | Punteggio |
|---------|-----------|
| Orario lavorativo (8:00-20:00) | +20 |
| Rete Internal | +20 |
| Rete Production | +15 |
| Rete Development | +10 |
| Rete External | -10 |
| Weekend (non CEO/CTO) | -20 |

#### 5.1.3 Soglie di Accesso

| Trust Score | Livello di Accesso | Risorse Accessibili |
|-------------|-------------------|---------------------|
| ≥ 80 | Full Access | Tutte, incluso audit |
| 60-79 | Standard Access | employees, customers, orders, projects |
| 40-59 | Limited Access | stats, departments |
| < 40 | Denied | Nessuna |

### 5.2 Policy Decision Point (PDP)

**File:** `pdp/pdp.py`  
**Tecnologia:** Python 3.11 + Flask  
**Porta:** 5000

#### 5.2.1 Processo Decisionale

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROCESSO DECISIONALE PDP                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  1. CHECK IP        │
            ┌──────│     BLACKLIST       │──────┐
            │      └─────────────────────┘      │
     IP Blacklisted?                            │ NO
            │                                   ▼
            │                        ┌─────────────────────┐
            │                        │  2. CALCULATE       │
            │                        │    TRUST SCORE      │
            │                        └─────────────────────┘
            │                                   │
            │                                   ▼
            │                        ┌─────────────────────┐
            │                        │  3. CHECK MINIMUM   │
            │                        │  TRUST FOR RESOURCE │
            │                        └─────────────────────┘
            │                                   │
            │                         Trust < Min?
            │                         │         │
            │                        YES        NO
            │                         │         │
            │                         │         ▼
            │                         │ ┌─────────────────────┐
            │                         │ │  4. CHECK ROLE      │
            │                         │ │     PERMISSION      │
            │                         │ └─────────────────────┘
            │                         │         │
            │                         │  Role Not Allowed?
            │                         │   │           │
            │                         │  YES          NO
            │                         │   │           │
            │                         │   │           ▼
            │                         │   │ ┌─────────────────────┐
            │                         │   │ │  5. CHECK ACTION    │
            │                         │   │ │     PERMISSION      │
            │                         │   │ └─────────────────────┘
            │                         │   │         │
            │                         │   │  Action Denied?
            │                         │   │   │         │
            │                         │   │  YES        NO
            ▼                         ▼   ▼   │         │
     ┌──────────────────────────────────────┘         │
     │                                                 │
     ▼                                                 ▼
┌─────────┐                                     ┌─────────┐
│  DENY   │                                     │  ALLOW  │
└─────────┘                                     └─────────┘
```

#### 5.2.2 API Endpoints

| Endpoint | Metodo | Descrizione |
|----------|--------|-------------|
| `/evaluate` | POST | Valuta una richiesta di accesso |
| `/trust-score` | POST | Calcola solo il Trust Score |
| `/policies` | GET | Restituisce le policy attive |
| `/health` | GET | Health check |

### 5.3 Policy Enforcement Point (PEP)

**File:** `pep/pep.js`  
**Tecnologia:** Node.js 18 + Express  
**Porta:** 8080

Il PEP funge da gateway per tutte le richieste, implementando:

1. **Verifica JWT** tramite JWKS (Keycloak)
2. **Analisi IDS** consultando Snort
3. **Consultazione PDP** per decisione
4. **Accesso Database** come client PostgreSQL
5. **Enforcement** della decisione

#### 5.3.1 Risorse Protette

| Endpoint | Risorsa | Trust Minimo | Ruoli Autorizzati |
|----------|---------|--------------|-------------------|
| `/api/db/employees` | employees | 50 | CEO, CTO, HR Manager, Developer, Analyst |
| `/api/db/customers` | customers | 60 | CEO, CTO, Sales Manager, Analyst |
| `/api/db/orders` | orders | 60 | CEO, CTO, Sales Manager, Analyst |
| `/api/db/projects` | projects | 50 | CEO, CTO, Developer, Analyst |
| `/api/db/audit` | audit | 80 | CEO, CTO |
| `/api/db/stats` | stats | 40 | Tutti i ruoli |

### 5.4 Snort IDS

**File:** `snort-ids/snort_api.py`  
**Tecnologia:** Python + Snort 3  
**Porta:** 9090

#### 5.4.1 Regole Implementate (36 totali)

| Categoria | Regole | Severità | Azione |
|-----------|--------|----------|--------|
| SQL Injection | 7 | Critical | Block |
| Cross-Site Scripting (XSS) | 5 | High | Block |
| Path Traversal | 3 | High | Block |
| Command Injection | 6 | Critical | Block |
| Scanner Detection | 5 | Medium | Alert |
| Sensitive File Access | 4 | Critical | Block |
| Blocked IPs | 3 | High | Block |
| Protocol Anomalies | 2 | Medium | Alert |
| Data Exfiltration | 1 | High | Alert |

#### 5.4.2 Esempi di Regole

```snort
# SQL Injection - UNION SELECT
alert tcp any any -> any any (msg:"SQLI-001 SQL Injection - UNION SELECT"; 
    content:"union"; nocase; content:"select"; nocase; distance:0; within:20; 
    classtype:web-application-attack; sid:1000001; rev:3;)

# XSS - Script Tag
alert tcp any any -> any any (msg:"XSS-001 Cross-Site Scripting - Script Tag"; 
    content:"<script"; nocase; 
    classtype:web-application-attack; sid:1000010; rev:3;)

# Path Traversal
alert tcp any any -> any any (msg:"TRAV-001 Path Traversal - Dot Dot Slash"; 
    content:"../"; 
    classtype:web-application-attack; sid:1000020; rev:3;)
```

### 5.5 Firewall Multi-Livello

#### 5.5.1 Layer 3 - iptables

**File:** `iptables-firewall/firewall_proxy.py`

| Lista | IP | Azione |
|-------|-----|--------|
| **Blacklist** | 172.28.1.200 | DROP |
| **Blacklist** | 172.28.1.250 | DROP |
| **Blacklist** | 172.28.1.60 | DROP |
| **Whitelist** | 172.28.1.100 | ACCEPT |
| **Whitelist** | 172.28.1.50 | ACCEPT |

#### 5.5.2 Layer 7 - Squid

**File:** `squid-proxy/squid.conf`

**ACL implementate:**
- Domain blacklist (file esterno)
- URL pattern matching (SQL Injection, XSS)
- Suspicious file extensions (.exe, .bat, .ps1)
- Path traversal patterns

### 5.6 Utenti e Ruoli

| Username | Password | Ruolo | Dipartimento |
|----------|----------|-------|--------------|
| m.rossi | Ceo2024! | CEO | Executive |
| l.bianchi | Cto2024! | CTO | Technology |
| g.ferrari | Hr2024! | HR Manager | Human Resources |
| a.romano | Sales2024! | Sales Manager | Sales |
| f.colombo | Dev2024! | Developer | IT |
| s.ricci | Analyst2024! | Analyst | Analytics |

---


## 6. 🧪 Testing e Validazione

### 6.1 Piano di Test

| ID | Categoria | Descrizione | Risultato Atteso |
|----|-----------|-------------|------------------|
| T01 | Autenticazione | Login con credenziali valide | Token JWT rilasciato |
| T02 | Autenticazione | Login con credenziali invalide | 401 Unauthorized |
| T03 | Autorizzazione | Accesso risorsa con Trust Score sufficiente | 200 OK + dati |
| T04 | Autorizzazione | Accesso risorsa con Trust Score insufficiente | 403 Forbidden |
| T05 | Autorizzazione | Accesso da IP blacklist | Connessione rifiutata |
| T06 | IDS | SQL Injection attempt | Request blocked |
| T07 | IDS | XSS attempt | Request blocked |
| T08 | IDS | Path Traversal attempt | Request blocked |
| T09 | Firewall L7 | Accesso a dominio bloccato | 403 Forbidden |
| T10 | RBAC | CEO accede ad audit | 200 OK |
| T11 | RBAC | Developer accede ad audit | 403 Forbidden |
| T12 | Trust Score | Verifica calcolo componenti | Score corretto |

### 6.2 Scenari di Test Implementati

#### Scenario 1: Accesso Legittimo da Rete Interna

```bash
# Developer accede a employees dalla rete development
curl -X GET http://pep:8080/api/db/employees \
  -H "Authorization: Bearer $DEV_TOKEN"
```

**Risultato atteso:** Trust Score ~75, Access ALLOWED

#### Scenario 2: Accesso da IP Blacklist

```bash
# Tentativo da 172.28.1.200 (blocked)
curl -X GET http://172.28.1.254:8080/api/db/employees
```

**Risultato atteso:** Connessione DROP a livello iptables

#### Scenario 3: SQL Injection

```bash
curl -X GET "http://pep:8080/api/db/employees?id=1' UNION SELECT * FROM users--"
```

**Risultato atteso:** Blocked by Snort IDS (SQLI-001)

#### Scenario 4: Accesso a Risorsa Riservata

```bash
# Developer tenta accesso ad audit (richiede trust >= 80)
curl -X GET http://pep:8080/api/db/audit \
  -H "Authorization: Bearer $DEV_TOKEN"
```

**Risultato atteso:** 403 Forbidden - Trust insufficiente per risorsa audit

### 6.3 Risultati dei Test

| Test ID | Esito | Note |
|---------|-------|------|
| T01 | ✅ PASS | Token JWT valido rilasciato |
| T02 | ✅ PASS | 401 restituito correttamente |
| T03 | ✅ PASS | Dati restituiti con Trust Score |
| T04 | ✅ PASS | 403 con motivo dettagliato |
| T05 | ✅ PASS | Pacchetti DROPpati da iptables |
| T06 | ✅ PASS | Alert SQLI-001, request blocked |
| T07 | ✅ PASS | Alert XSS-001, request blocked |
| T08 | ✅ PASS | Alert TRAV-001, request blocked |
| T09 | ✅ PASS | Squid nega accesso |
| T10 | ✅ PASS | CEO accede con trust 93+ |
| T11 | ✅ PASS | Developer riceve 403 |
| T12 | ✅ PASS | Componenti calcolati correttamente |

### 6.4 Video Demo degli Scenari di Test

Di seguito sono presentati i video dimostrativi che illustrano il funzionamento dell'architettura Zero Trust in scenari reali.

---

#### 📹 Scenario 1: Accesso dalla Rete Interna al Database


https://github.com/user-attachments/assets/7abedd12-9639-4e9b-951e-37550c8f9bdc



**Cosa succede in questo video:**

1. **Autenticazione iniziale**: Un utente dalla rete interna (development o production) effettua una richiesta al PEP (Policy Enforcement Point) includendo il proprio token JWT ottenuto da Keycloak.

2. **Validazione del token**: Il PEP verifica la validità del token JWT consultando il JWKS endpoint di Keycloak, estraendo le informazioni sull'utente (username, ruolo, preferred_username).

3. **Richiesta al PDP**: Il PEP inoltra la richiesta al Policy Decision Point con tutti i parametri contestuali: IP sorgente, risorsa richiesta, azione (GET/POST/DELETE), e informazioni utente.

4. **Calcolo del Trust Score**: Il PDP calcola dinamicamente il Trust Score considerando:
   - **Role Score (30%)**: Punteggio basato sul ruolo dell'utente (CEO=100, Developer=70, ecc.)
   - **History Score (25%)**: Percentuale di accessi passati riusciti consultando Splunk
   - **Anomaly Score (25%)**: Presenza di alert IDS recenti associati all'utente
   - **Context Score (20%)**: Bonus per rete interna (+20), orario lavorativo (+20)

5. **Decisione e accesso**: Con un Trust Score elevato (~75-85 per un developer interno), il PDP autorizza l'accesso. Il PEP inoltra la richiesta al database PostgreSQL e restituisce i dati all'utente.

6. **Logging**: Tutti gli eventi vengono inviati a Splunk per analisi storica e audit.

---

#### 📹 Scenario 2: Tentativo di Accesso dalla Rete Esterna al Database


https://github.com/user-attachments/assets/8fb2df13-3802-4204-a9c6-49121da5b212



**Cosa succede in questo video:**

1. **Richiesta da rete esterna**: Un host situato nella rete esterna (external-zone, 172.28.4.0/24) tenta di accedere al database aziendale attraverso il PEP.

2. **Controllo firewall Layer 3**: La richiesta attraversa prima il firewall iptables che verifica:
   - Se l'IP sorgente è nella blacklist (172.28.1.200, 172.28.4.200)
   - Se la comunicazione tra le zone di rete è permessa
   - Applicazione delle regole di filtraggio configurate

3. **Ispezione Snort IDS**: Il traffico viene analizzato da Snort che cerca pattern sospetti:
   - Tentativi di SQL Injection
   - Attacchi XSS
   - Path Traversal
   - Altre 36 regole custom definite in `local.rules`

4. **Valutazione PDP con penalità**: Il PDP riceve la richiesta e calcola il Trust Score con penalità per la rete esterna:
   - **Context Score ridotto**: La provenienza dalla rete esterna comporta un malus (-10 punti)
   - **Trust Score finale più basso**: Tipicamente 50-65 per utenti esterni

5. **Possibili esiti**:
   - **Accesso limitato**: Se il Trust Score è tra 40-59, l'utente può accedere solo a risorse a bassa sensibilità (stats, departments)
   - **Accesso negato**: Se il Trust Score scende sotto 40 o la risorsa richiede privilegi elevati, il PDP nega l'accesso con codice 403

6. **Alert e monitoring**: Ogni tentativo viene loggato in Splunk con dettagli sulla decisione, permettendo analisi di pattern sospetti.

---

#### 📹 Scenario 3: Comunicazione dalla Rete Interna verso la Rete Esterna



https://github.com/user-attachments/assets/4c081787-5e64-4855-a8e4-7b7c605e8595


**Cosa succede in questo video:**

1. **Richiesta outbound**: Un host dalla rete interna (development o production) tenta di comunicare con un server esterno, ad esempio per scaricare risorse o contattare API esterne.

2. **Proxy Squid (Layer 7)**: Tutto il traffico HTTP/HTTPS in uscita passa attraverso il proxy Squid che opera a livello applicativo:
   - **Verifica dominio**: Squid controlla se il dominio di destinazione è nella blacklist (`blocked_domains.txt`)
   - **Domini bloccati**: malware.com, phishing-site.com, blocked-external.com, ecc.
   - **Pattern matching**: Ricerca di URL sospetti o tentativi di esfiltrazione dati

3. **Scenari di blocco**:
   - **Dominio in blacklist**: Squid restituisce HTTP 403 Forbidden e logga l'evento
   - **Pattern malevolo rilevato**: La richiesta viene bloccata e segnalata

4. **Scenari di autorizzazione**:
   - **Dominio consentito**: La richiesta viene inoltrata al server esterno (es. allowed-external.com)
   - **Risposta proxy**: Squid riceve la risposta e la inoltra al client interno

5. **Logging centralizzato in Splunk**: 
   - Ogni richiesta (permessa o bloccata) viene registrata
   - I log includono: timestamp, IP sorgente, dominio destinazione, esito, user-agent
   - Dashboard Splunk permettono di visualizzare pattern di traffico e anomalie

6. **Integrazione con il sistema Zero Trust**: Anche se la comunicazione è outbound, il sistema mantiene visibilità completa sulle attività di rete, permettendo di identificare:
   - Host compromessi che tentano comunicazioni con C&C server
   - Tentativi di data exfiltration
   - Violazioni delle policy aziendali sull'uso di internet

---

> **Nota:** I video sono stati registrati durante sessioni di test reali del sistema e mostrano output autentici dei vari componenti (PDP, PEP, Snort IDS, Splunk).

---


## 7. 🔒 Analisi di Sicurezza

### 7.1 Threat Model

| Threat | Vettore di Attacco | Mitigazione | Componente |
|--------|-------------------|-------------|------------|
| **Unauthorized Access** | Credenziali rubate | MFA (futuro), Trust Score dinamico | PDP, Keycloak |
| **SQL Injection** | Input malevolo | Snort IDS + Squid pattern matching | Snort, Squid |
| **XSS** | Script injection | IDS detection + input sanitization | Snort |
| **Lateral Movement** | Compromissione host | Micro-segmentazione, verifica continua | Network, PEP |
| **Insider Threat** | Utente malevolo | Trust Score, logging, anomaly detection | PDP, SIEM |
| **Session Hijacking** | Token rubato | JWT con expiry breve, JWKS validation | PEP, Keycloak |

### 7.2 Controlli di Sicurezza Implementati

| Controllo | Implementazione | Copertura |
|-----------|-----------------|-----------|
| **Authentication** | JWT + JWKS (Keycloak) | Tutte le richieste |
| **Authorization** | RBAC + Trust Score | Per-risorsa |
| **Input Validation** | Snort rules + Squid ACL | Layer 7 |
| **Network Segmentation** | 5 subnet isolate | Infrastructure |
| **Logging & Monitoring** | Splunk SIEM | 100% eventi |
| **Intrusion Detection** | Snort inline | Traffico PEP |

### 7.3 Vulnerabilità Note e Mitigazioni Future

| Vulnerabilità | Rischio | Mitigazione Proposta |
|---------------|---------|---------------------|
| Single PDP instance | Single Point of Failure | Clustering con load balancing |
| Password-only auth | Credential theft | Implementare MFA |
| Static blacklist | Evasione IP | Threat intelligence feed |
| Signature-based IDS | Zero-day attacks | ML-based anomaly detection |

---

## 8. 💬 Discussione

### 8.1 Obiettivi Raggiunti

| Obiettivo | Stato | Evidenza |
|-----------|-------|----------|
| Implementare PDP/PEP | ✅ Raggiunto | Componenti funzionanti e testati |
| Trust Score dinamico | ✅ Raggiunto | 4 componenti, calcolo real-time |
| Integrazione tool enterprise | ✅ Raggiunto | Snort, Splunk, Squid, iptables, PostgreSQL |
| Scenari di test realistici | ✅ Raggiunto | 15 scenari, 100% pass rate |
| Containerizzazione | ✅ Raggiunto | Docker Compose completo |
| Documentazione | ✅ Raggiunto | README completo + commenti codice |

### 8.2 Limitazioni del Progetto

1. **Trust Score statico per nuovi utenti**: Il sistema assegna un trust score di default (70) per utenti senza storico. Un attaccante potrebbe sfruttare questa finestra temporale.

2. **Single Point of Failure (PDP)**: Il PDP è un singolo nodo. In produzione sarebbe necessario un cluster con load balancing per garantire alta disponibilità.

3. **IDS basato su signature**: Snort rileva solo pattern noti. Attacchi zero-day o tecniche di evasione avanzate potrebbero non essere rilevati.

4. **Assenza di MFA**: L'autenticazione si basa solo su password + JWT. L'aggiunta di un secondo fattore aumenterebbe significativamente la sicurezza.

5. **Blacklist statica**: Le liste di IP bloccati sono statiche. In un ambiente reale dovrebbero essere aggiornate dinamicamente da feed di threat intelligence.

### 8.3 Lavori Futuri

1. **Machine Learning per Anomaly Detection**: Integrare un modello ML (es. Isolation Forest) per rilevare comportamenti anomali non basati su signature.

2. **Behavioral Analytics**: Estendere il Trust Score con User and Entity Behavior Analytics (UEBA) per analisi comportamentale avanzata.

3. **Zero Trust Network Access (ZTNA)**: Estendere l'architettura per supportare accesso remoto sicuro, eliminando la necessità di VPN.

4. **Continuous Authentication**: Implementare ri-autenticazione periodica basata su risk score e cambio di contesto.

5. **Threat Intelligence Integration**: Collegare le blacklist a feed esterni (es. AlienVault OTX, AbuseIPDB) per aggiornamenti automatici.

6. **Service Mesh Integration**: Integrare con Istio o Linkerd per Zero Trust a livello di microservizi.

## 9. ✅ Conclusioni

Il presente progetto ha implementato con successo un'architettura Zero Trust completa, dimostrando la fattibilità e l'efficacia del paradigma "Never Trust, Always Verify" in un ambiente enterprise simulato.

I risultati principali includono:

- **Trust Score dinamico** che combina 4 fattori (ruolo, storico, anomalie, contesto) per decisioni di accesso granulari
- **Defense in Depth** con 4 livelli di protezione (iptables → Squid → Snort → PDP)
- **Logging centralizzato** con Splunk per visibilità completa e analisi forense
- **100% dei test superati** validando l'efficacia delle protezioni implementate

L'architettura rispetta le linee guida NIST SP 800-207 e può essere estesa per supportare scenari enterprise più complessi, come indicato nella sezione Lavori Futuri.

Il codice sorgente, la documentazione e gli script di test sono disponibili nel repository allegato, permettendo la riproduzione completa dell'ambiente e la verifica dei risultati.

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



</div>

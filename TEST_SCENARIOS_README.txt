================================================================================
                    TechCorp Zero Trust Architecture
                    Istruzioni Script Scenari di Test
================================================================================

PANORAMICA
--------
Lo script test_scenarios.sh e' una suite di Unit Test e Test End-to-End che
valida tutti i principi della Zero Trust Architecture implementati in questo
progetto.


PREREQUISITI
-------------
1. Docker e Docker Compose installati aul proprio sistema
2. Tutti i servizi in esecuzione: docker-compose up -d --build
3. Attendere fino a 5 minuti per l'inizializzazione di tutti i servizi (specialmente Splunk e Keycloak)
4. curl e awk installati sul proprio sistema


COME ESEGUIRE
----------
Dalla directory radice del progetto:

    chmod +x test_scenarios.sh
    ./test_scenarios.sh

Lo script eseguira' circa 30 test attraverso 7 sezioni e visualizzera' 
l'esito di ogni test (PASSATO/FALLITO).


ENDPOINT DEI SERVIZI
--------------------
| Servizio         | Endpoint                  |
|------------------|---------------------------|
| PEP              | http://localhost:8080     |
| PDP              | http://localhost:5000     |
| Keycloak         | http://localhost:8180     |
| Snort IDS        | http://localhost:9090     |
| IPTables FW      | http://localhost:8888     |
| Squid Proxy      | http://localhost:3129     |
| Firewall Proxy   | http://localhost:8081     |

---------------

SEZIONE 1: Verifica Stato Componenti (Unit Test)
    - Verifica che tutti i componenti ZTA siano operativi
    - Componenti testati:
        * PDP (Policy Decision Point)
        * PEP (Policy Enforcement Point)
        * Snort IDS (Intrusion Detection System)
        * Firewall IPTables (Layer 3)
        * Squid Proxy (Layer 7)
        * Keycloak (Identity Provider)

SEZIONE 2: Test di Autenticazione
    - Testa il flusso di autenticazione OAuth2/OIDC tramite Keycloak
    - Casi di test:
        * Credenziali valide (CEO m.rossi): Token JWT ottenuto
        * Credenziali non valide: Correttamente rifiutate con errore

SEZIONE 3: Test Calcolo Trust Score
    - Testa la formula dinamica del trust score con diversi scenari
    - NOTA: Il trust score varia dinamicamente in base agli eventi di sicurezza
    - Casi di test:
        * CEO da Rete Produzione (172.28.4.10): Atteso >= 75
        * Developer da Rete Sviluppo (172.28.5.10): Atteso 65-95
        * Analyst da IP Esterno Whitelisted (172.28.1.100): Atteso 55-85
        * Qualsiasi utente da IP Blacklisted (172.28.1.200): Atteso <= 15

SEZIONE 4: Test RBAC - Role-Based Access Control
    - Testa che l'accesso richieda SIA fiducia sufficiente CHE ruolo autorizzato
    - Casi di test:
        * A1: CEO accede ad audit: PERMESSO (ha ruolo admin + fiducia)
        * B1: HR Manager accede ad audit: NEGATO (ruolo non autorizzato)
        * B5: Sales Manager accede a employees: NEGATO (ruolo non in lista)
        * A5: Sales Manager accede a customers: PERMESSO (ha ruolo)
        * A7: Developer accede a projects: PERMESSO (ha ruolo)
        * B8: Developer accede a customers: NEGATO (ruolo non in lista)
        * A9: Analyst accede a customers: Dipende dal trust (>= 60)
        * B3: Developer accede ad audit: NEGATO (non autorizzato)

SEZIONE 5: Test Sicurezza di Rete (Firewall L3/L7)
    - Testa il filtraggio basato su IP a Livello 3 e Livello 7
    - Casi di test:
        * Firewall L3: Verifica IP in blacklist (172.28.1.200) -> BLOCCATO
        * Firewall L3: Verifica IP in whitelist (172.28.1.100) -> PERMESSO
        * E2E: Firewall Proxy raggiungibile (porta 8081)
        * Policy: Richiesta da IP in blacklist valutata e negata dal PDP

SEZIONE 6: Test Intrusion Detection System (Snort)
    - Testa l'ispezione profonda dei pacchetti e il rilevamento attacchi
    - Tipi di attacco testati:
        * SQL Injection: SELECT * FROM users WHERE id=1 OR 1=1; DROP TABLE
        * Cross-Site Scripting (XSS): <script>alert(document.cookie)</script>
        * Path Traversal: /../../../etc/passwd
    - Test End-to-End:
        * Tentativo SQL Injection attraverso il PEP

SEZIONE 7: Impatto del Trust Score sull'Accesso
    - Testa come il trust score influenza le decisioni di accesso
    - Casi di test:
        * CTO da IP esterno sconosciuto (172.28.1.150) accede ad audit:
          NEGATO (trust score sotto soglia 80 richiesta per audit)
        * CEO dalla rete interna (172.28.2.30) accede a stats:
          PERMESSO (trust score sufficiente)


OUTPUT ATTESO
---------------
Se tutti i servizi funzionano correttamente:

    Test Totali: ~30
    Passati: ~30
    Falliti: 0

    ==============================================================
       TUTTI I TEST PASSATI - Architettura Zero Trust Funzionante
    ==============================================================

NOTA: Alcuni test possono avere
risultati variabili in base allo stato dinamico del sistema. 
Alcuni esiti FALLITO possono dipendere da un basso trust score dovuto 
dai diversi test eseguiti sull'IDS (penalita' dell'anomaly score).

ALCUNI PROBLEMI
---------------
Se i test falliscono:

1. Servizi non pronti:
   - Attendere 2-3 minuti dopo docker-compose up
   - Controllare: docker-compose ps (container "Up" o "healthy")

2. Autenticazione Keycloak fallisce:
   - Verificare completamento keycloak-init: docker logs keycloak-init
   - Controllare accessibilita' Keycloak: curl http://localhost:8180/realms/techcorp

3. Test IDS falliscono:
   - Controllare esecuzione Snort: curl http://localhost:9090/health
   - Visualizzare log Snort: docker logs snort-ids

4. Firewall non risponde:
   - Verificare IPTables: curl http://localhost:8888/health
   - Verificare Firewall Proxy: curl http://localhost:8081/


PRINCIPI ZERO TRUST
----------------------------------
1. NON FIDARSI MAI, VERIFICARE SEMPRE

2. ACCESSO CON PRIVILEGIO MINIMO

3. ASSUMERE LA VIOLAZIONE

4. VERIFICA CONTINUA


ANALISI AGGIUNTIVE
--------------------

- Console Admin Keycloak: http://localhost:8180/admin
  Login: admin / TechCorp2024!

- Visualizza Regole IDS:
  curl http://localhost:9090/rules | python3 -m json.tool

- Visualizza Stato Firewall:
  curl http://localhost:8888/status | python3 -m json.tool

- Visualizza Policy PDP:
  curl http://localhost:5000/policies | python3 -m json.tool


UTENTI TEST DISPONIBILI
--------------------
| Username    | Ruolo         | Password      |
|-------------|---------------|---------------|
| m.rossi     | CEO           | Ceo2024!      |
| l.bianchi   | CTO           | Cto2024!      |
| g.ferrari   | HR Manager    | Hr2024!       |
| a.romano    | Sales Manager | Sales2024!    |
| f.colombo   | Developer     | Dev2024!      |
| s.ricci     | Analyst       | Analyst2024!  |


CONFIGURAZIONE RETE
---------------------
| Rete            | Sottorete       | Descrizione             |
|-----------------|-----------------|-------------------------|
| Produzione      | 172.28.4.0/24   | Trust piu' alto         |
| Sviluppo        | 172.28.5.0/24   | Trust alto              |
| Interna         | 172.28.2.0/24   | Trust medio             |
| DMZ             | 172.28.3.0/24   | Trust ridotto           |
| Esterna WL      | 172.28.1.100    | Whitelist esterna       |
| Blacklistata    | 172.28.1.200    | BLOCCATA (trust <= 15)  |

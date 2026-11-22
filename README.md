Client-Side Desynchronization (CSD) Vulnerability Detection Script — v2
=========================================================================

Rilevamento di vulnerabilità di Client-Side Desync (CSD) secondo la
metodologia pubblicata da PortSwigger:
  - https://portswigger.net/web-security/request-smuggling/browser/client-side-desync
  - https://portswigger.net/research/browser-powered-desync-attacks

SOLO per test di bug bounty / pentest autorizzati sui propri target.

Rispetto alla v1, questa versione corregge un problema di fondo e fa un
refactor strutturale:

  1) BUG DI FONDO RISOLTO - trasporto HTTP
     La v1 inviava le richieste con la libreria `requests`, dichiarando un
     Content-Length più lungo del body passato. Ma `requests`/urllib3
     ricalcolano sempre Content-Length in base al body che gli passi e
     sovrascrivono qualunque header manuale: di fatto la v1 non inviava mai
     il mismatch che credeva di inviare, quindi i risultati non erano
     attendibili. Qui le richieste vengono costruite a mano e inviate su
     socket raw (RawHTTPClient): il Content-Length dichiarato copre solo un
     body "visibile" (6 byte), ma sullo stesso invio vengono spediti anche
     dei byte "nascosti" subito dopo (una seconda richiesta GET con un id
     univoco). Se il server si ferma esattamente al Content-Length
     dichiarato, quei byte restano nel buffer della connessione e possono
     essere interpretati come l'inizio della richiesta pipeline successiva:
     è il segnale di desync che lo script cerca di rilevare.
     NB: questo rimane un test "infrastrutturale" di tolleranza alla
     ambiguità di framing (nello spirito dei tool di request-smuggling
     detection). Non riproduce i quirk specifici del motore di un browser:
     una vulnerabilità CSD va comunque confermata con la PoC browser che lo
     script genera in fondo al report.

  2) ALTRI BUG RISOLTI
     - `confirm_vulnerability` nella v1 creava una `fresh_session` ma non la
       usava mai: ogni conferma riusava comunque la sessione originale. Qui
       ogni probe apre comunque una connessione TCP nuova, quindi il
       problema non si pone.
     - `test_error_triggering_payloads` nella v1 costruiva una lista
       `error_tests` (header malformati) che non veniva mai iterata: codice
       morto, rimosso.

  3) REFACTOR STRUTTURALE
     - dataclass `ProbeResult` al posto dei dict sciolti;
     - `logging` al posto di `print` (livello configurabile con -v);
     - report anche in JSON (--json-report);
     - liste di endpoint/redirect/payload personalizzabili da file
       (--endpoints-file, --redirect-candidates-file, --traversal-payloads-file);
     - soglie di conferma configurabili (--confirmations, --confidence-threshold);
     - --insecure per target con certificati self-signed;
     - nessuna dipendenza esterna: usa solo la libreria standard (prima
       serviva `requests`).

  4) SCOPERTA ENDPOINT REALI (--crawl)
     Le liste di default sono indovinate (favicon.ico, /admin, ...): su un
     target reale possono non esistere affatto, sprecando probe a vuoto. Con
     --crawl lo script fa un piccolo crawl same-origin della home page
     (html.parser di libreria standard, nessuna dipendenza nuova) e legge
     anche robots.txt/sitemap.xml, poi:
       - le pagine collegate/linkate (pubbliche, confermate esistenti)
         arricchiscono la lista di endpoint "statici";
       - le entry "Disallow" di robots.txt (tipicamente path non linkati,
         come i pannelli di amministrazione) arricchiscono la lista dei
         candidati di redirect.
     Le liste indovinate restano comunque utili insieme al crawl, perché
     servono proprio a coprire i path non raggiungibili da un crawler
     (non linkati pubblicamente).
"""

# AIFinancialCrime — Entwicklungsjournal

## Projekt
Ziel: Forensisches Bitcoin-Analyse-Tool
Repo: https://github.com/ordinalsog-ctrl/AIFinancialCrime
Starten: cd ~/AIFinancialCrime && lsof -ti:8000 | xargs kill -9 2>/dev/null && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
Browser: http://localhost:8000/intake

## Pi 5 Node
IP: 192.168.178.93, SSH: jonasweiss@192.168.178.93
Datadir: /mnt/bitcoin_1tb/.bitcoin
Status: bitcoin-cli -datadir=/mnt/bitcoin_1tb/.bitcoin getblockchaininfo
Reconnect: sudo mount /dev/sda1 /mnt/bitcoin_1tb && sudo systemctl start bitcoind
Sync: Block 941470 (100%), txindex: true

## API Keys
BLOCKCHAIR_API_KEY=PA__gj5kX0SKPwN1qv10LNnCzCKLnKAq
CHAINALYSIS_API_KEY=313a3ad73801d615d2326dd8cd8ac8a9d733fdf209bfa8fcc207da1646f2a092

## Wichtige Dateien (NIEMALS DUPLIKATE ERSTELLEN)
main.py — FastAPI Entry Point
src/api/report_endpoint.py — EINZIGER API Endpoint
src/investigation/generate_case_report.py — EINZIGER PDF Generator
frontend/index.html — Browser Interface

## Roadmap & Meilensteine

### Phase 1: Report-Modul (aktuell)

**Meilenstein I — Exchange-Erkennung (PRIO 1, aktiv)**
- Exchange-Zuordnung ist Fundament des gesamten Algorithmus
- Ohne zuverlässige Erkennung: unsauberer Report, falsche Hop-Kette, endloses Tracing
- Ziel: maximale Abdeckung bekannter Exchange-Adressen
- Aktuelle Quellen: WalletExplorer (gratis), Blockchair (API-Key vorhanden)
- Downstream-Analyse (1-2 Hop) als Fallback für Deposit-Adressen
- Nächste Schritte: weitere kostenlose/günstige Quellen evaluieren, lokale DB mit bekannten Adressen
- Risiko bei Falscherkennung: Chain endet zu früh (false positive) oder läuft endlos (false negative)

**Meilenstein II — Report-Qualität (nach Exchange-Stabilität)**
- Transaktionsgraph übersichtlicher, verständlicher, sauberer gestalten
- Gezieltere Daten für Behörden und Exchanges liefern
- Freeze-Request optimieren (alle betroffenen Adressen, Gesamtbetrag, Beweiskette)
- Report-Struktur für internationale Strafverfolgung (Europol, BaFin etc.)

### Phase 2: Forensik-Modul (nach Report-Abschluss)

- Setzt am Ende der L1-Kette an (wo Report aufhört)
- Exchange-interne Analyse: Gab es zeitgleich eine Auszahlung mit selbiger UTXO?
- Heuristische Tracking-Methoden: Zeitkorrelation, Betrags-Matching, Cluster-Analyse
- Eigene Heuristik des Benutzers: manuelle Recherche-Tools, eigene Hypothesen testen
- L2/L3 Befunde, klar als nicht-beweiskräftig markiert

### Phase 3: Feinschliff (nach Report + Forensik)

- Stabilität, Fehlerbehandlung, Edge Cases
- Usability: UI/UX, Onboarding, Hilfe-Texte
- Performance: Caching, Rate-Limit-Management, parallele API-Calls
- Deployment: Docker, CI/CD, Monitoring

---

## Session 2026-03-21 — Was wurde gemacht

### Gegenüber letztem Stand geändert

**`src/api/report_endpoint.py`** — alle Änderungen dieser Session:

1. **Block-Enrichment in `_get_tx()`** (NEU)
   - RPC `getrawtransaction` liefert kein `blockheight`, nur `blockhash`
   - Nach RPC-Call wird Blockstream `/api/tx/{txid}` nachgefragtum `status.block_height` und `block_time` zu ergänzen
   - Vorher: alle Hops zeigten Block 0. Jetzt: korrekte Blockhöhe in allen Hops

2. **Hop 0 Betrag-Fix** (KORRIGIERT)
   - Vorher: Summe aller Opfer-Inputs (z.B. 0.08599603 BTC) als gestohlener Betrag
   - Jetzt: Output an Empfänger-Adresse (z.B. 0.02459629 BTC) = tatsächlich gestohlener Betrag
   - Fallback auf Input-Summe nur wenn kein Recipient-Output gefunden

3. **Exchange-Attribution erweitert** (NEU)
   - `_downstream_exchange_lookup()`: Wenn WalletExplorer/Blockchair die Adresse selbst nicht kennen, wird die Spending-TX analysiert. Outputs dieser TX werden auf bekannte Exchanges geprüft. Wenn ein Output erkannt → Originaladresse ist Deposit-Adresse dieser Exchange (L2, Beweiskette: Adresse → Sweep-TX → bekannte Exchange-Adresse)
   - Blockchair jetzt auch im Downstream-Lookup aktiv (nicht nur WalletExplorer)
   - TX-Count-Heuristik wurde ENTFERNT (nicht gerichtsfest)

4. **Manuelle Attribution** (NEU)
   - `ReportRequest` hat neues Feld `manual_attributions: dict[str, str]`
   - Frontend: "Als Exchange markieren" Button pro Output-Adresse
   - Override für Fälle wo Downstream-Analyse versagt

5. **Split-Branch-Fix** (KORRIGIERT)
   - Vorher: 10%-Schwellwert filterte kleine Split-Branches heraus
   - Jetzt: Dust-Limit (546 sats) — alle relevanten Outputs werden verfolgt
   - Vorher: `if not exchange_hits:` blockierte Queuing aller Branches wenn Exchange erkannt
   - Jetzt: Nicht-Exchange Outputs werden immer gequeued (unabhängig von Exchange-Hits)

6. **Pooling-Erkennung** (NEU)
   - Wenn Output-Betrag > 3x des getrackten Betrags → Pooling/Konsolidierung erkannt
   - Confidence wechselt von L1 → L2 mit explizitem Hinweis im Report
   - Tracing stoppt (L1 nicht mehr haltbar wenn fremde Funds zusammengeführt wurden)
   - Exchange-Erkennung hat Vorrang vor Pooling-Erkennung

7. **Chain-Tracer Early Exit für bekannte Exchange-Adressen** (NEU)
   - Wenn `current_address` bereits im Cache als Exchange → sofortiger Stop ohne weitere TX-Analyse
   - Verhindert dass Tracing in Exchange-interne Wallet-Bewegungen läuft

**`frontend/index.html`** — Änderungen dieser Session:

1. **Täter-Adresse: Manuelle Auswahl statt Auto-Selektion** (KORRIGIERT)
   - Vorher: Größter Output automatisch als Täter markiert (falsch bei Change-Outputs)
   - Jetzt: "Als Täter markieren" Button pro Output — User entscheidet
   - "Als Exchange markieren" Button (blau) pro Output für manuelle Attribution

**`src/investigation/generate_case_report.py`** — Änderungen dieser Session:

1. **Hardcoded Inhalte entfernt** (KORRIGIERT)
   - Subtitle "Ledger Hardware Wallet" → dynamisch aus `CASE['wallet_type']`
   - Empfohlene Maßnahmen "Ledger" → dynamisch
   - Freeze-Request TX-Details → dynamisch aus `HOPS[0]`
   - Case-ID in Freeze-Request → dynamisch

### Was funktioniert (getestet)
- Block-Höhen in allen Hops korrekt
- Hop 0 Betrag korrekt (Output an Täter, nicht Input-Summe)
- Split-Branches werden vollständig verfolgt (beide Branches)
- Exchange-Erkennung via WalletExplorer + Blockchair + Downstream-Analyse
- Pooling wird erkannt und Chain korrekt beendet
- Testfall: `1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101`
  - Split auf `bc1qtrqkv3kk4...` und `bc1qtm8nrnm6n4...`
  - Beide gehen zu HTX (1DLymHytXsdD2Bhz7Ywa8JpGX7QsQFH1xr und TX 8d362e37...)
- Testfall: `35abe6ba553161896ce73187933350ac6c6e1effa23c8ae7b727829b59da4912`
  - Täteradresse: `14Kdp3j6h6c9nagKVNcszqdXwxQdGApt6A`
  - Chain folgt bis Kraken (Hop 7) — Binance-Erkennung für `14Kdp3...` noch offen (Downstream-Analyse findet `bc1qm34lsc...` nicht bei WalletExplorer/Blockchair)

### Offene Punkte (Modul 1) — Stand 2026-03-21
1. **Binance Deposit-Erkennung**: `14Kdp3j6h6c9nagKVNcszqdXwxQdGApt6A` wird nicht als Binance erkannt, weil die Sweep-Wallet `bc1qm34lsc65zpw791...` weder bei WalletExplorer noch Blockchair getaggt ist.
2. **Exchange-Erkennung allgemein**: Wenn Exchange nicht erkannt → Tracing läuft endlos. Wenn falsch erkannt → Chain endet zu früh. Beides schlecht für Report.

---

## Session 2026-03-22 — Was wurde gemacht

### Bugs gefixt (gegenüber 2026-03-21)

**`src/api/report_endpoint.py`**:

1. **Hardcoded-Daten komplett entfernt** — `generate_case_report.py` hatte CASE, HOPS, EXCHANGES_IDENTIFIED als Jonas-Weiss-Testdaten am Modul-Level. Jetzt leere Vorlagen (`CASE: dict = {}`, `HOPS: list = []`). Werden ausschliesslich von `report_endpoint.py` vor PDF-Generierung dynamisch gesetzt.

2. **Tracer Early-Exit für Recipient-Adresse deaktiviert** — Wenn `recipient_address` via Downstream als Exchange im Cache stand, brach der Tracer sofort ab (0 Hops). Fix: `is_initial_step = (current_address == recipient_address and current_txid == fraud_txid)` — erster Queue-Eintrag wird NIE durch Cache-Check abgebrochen.

3. **Recipient-Adresse aus Hop-0-Exchange-Scan entfernt** — `_check_address(recipient_address)` im Hop-0-Scan pollutete den Cache. Fix: `if addr == req.recipient_address: continue`.

4. **Change-Output Exchange-Check übersprungen** — `_check_address(current_address)` im Tracer-Output-Scan markierte den Täter selbst als Exchange (weil Downstream sah dass er AN Exchange sendet). Fix: `if addr == current_address: continue` in der Output-Scan-Loop.

5. **Direkte vs. Downstream-Erkennung getrennt** — `_check_address(addr, use_downstream=False)` im Tracer-Output-Scan. Deposit-Adressen werden nicht vorzeitig als Exchange markiert. L1-Kette läuft bis zur tatsächlichen Exchange-Adresse weiter. Downstream nur noch für Unspent-UTXO-Check.

6. **Intelligenter Cache** — `_downstream_checked` Flag im Cache. Wenn zuerst mit `use_downstream=False` geprüft → kein Exchange gefunden → gecacht. Späterer Aufruf mit `use_downstream=True` erkennt das Flag und prüft Downstream nach.

7. **Branch-Limit** — Max 5 Non-Exchange Outputs pro TX (Top N nach Betrag). Verhindert Queue-Explosion bei TXs mit vielen Outputs.

8. **Zusammenfassung: alle Exchange-Adressen anzeigen** — `_build_exchanges()` dedupliziert jetzt nach Adresse (nicht nach Exchange-Name). Bei 2x Huobi-Adressen erscheinen 2 Einträge.

9. **Freeze-Request gruppiert pro Exchange** — `_generate_freeze_requests()` gruppiert nach Exchange-Name. Ein Freeze-Request mit allen Adressen und Gesamtbetrag.

10. **Blockstream Retry** — `_get_tx()` hat 3 Versuche mit exponentialem Backoff bei Rate-Limiting.

### Testergebnisse (2026-03-22)
- TX `1f4bfff88...`: **5 Hops**, Split korrekt verfolgt, beide Pfade zu HTX/Huobi erkannt
  - Hop 0: Fraud TX → bc1qztlxu7... (L1)
  - Hop 1: 5e1e80ff → bc1qtm8nrnm6n4... (0.20 BTC) + bc1qztlxu7... (change)
  - Hop 2: 578dbd7a → bc1qtrqkv3kk4... (0.2124 BTC)
  - Hop 3: df8dd002 → 1DLymHytXsdD2Bhz7Ywa8JpGX7QsQFH1xr (WalletExplorer: Huobi ✓)
  - Hop 4: 8d362e37 → 1B2opjpPPJNVQHmCjyxqnGP6mLq4wQcPgg (WalletExplorer: Huobi ✓)
- Zusammenfassung zeigt beide Huobi-Adressen mit jeweiligem Betrag
- 1 Freeze-Request für Huobi (Gesamtbetrag ~0.41 BTC)
- Blockhöhen korrekt in allen Hops
- Keine hardcoded Daten mehr

### Nächste Schritte
→ **Meilenstein I**: Exchange-Erkennung stabilisieren (weitere TX testen, weitere Quellen)

---

## Session 2026-03-22b — Lokale Exchange-Datenbank (Meilenstein I, Stufe 1)

### Was wurde gemacht

**`sql/008_seed_exchange_addresses.sql`** — Neue Migration:

1. **Neue Attribution Sources**
   - `BLOCKCHAIR` (Priorität 5) — für persistent gespeicherte Blockchair API-Ergebnisse
   - `SEED_EXCHANGE` (Priorität 3, gleich nach OFAC) — für kuratierte Seed-Daten

2. **18 Exchange-Entities** registriert (Binance, Coinbase, Kraken, Huobi, OKX, Bybit, Bitfinex, Bitstamp, KuCoin, Gate.io, Gemini, Bittrex, BitMEX, Poloniex, Bitget, MEXC, Crypto.com, Upbit)

3. **49 bekannte Hot/Cold Wallet-Adressen** geseeded:
   - Binance: 11 Adressen (inkl. `bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h` — die Sweep-Wallet die vorher NICHT erkannt wurde)
   - Coinbase: 7, Kraken: 5, Huobi/HTX: 6, OKX: 3, Bybit: 2, Bitfinex: 3, Bitstamp: 2, KuCoin: 2, Gemini: 1, Gate.io: 1, BitMEX: 2, Poloniex: 1, Crypto.com: 2, Upbit: 1

**`src/api/report_endpoint.py`** — DB-Integration:

1. **`_db_exchange_lookup(address)`** (NEU) — Stufe 0 in der Exchange-Erkennung
   - Direkte SQL-Abfrage auf `address_attributions` (JOIN mit `attribution_sources`)
   - Kein API-Call, keine Latenz, keine Rate-Limits
   - Gibt kanonischen Exchange-Namen zurück (via `KNOWN_EXCHANGES` Mapping)

2. **`_db_persist_attribution(address, exchange_name, source_key)`** (NEU) — Persistent Cache
   - Speichert jedes WalletExplorer/Blockchair API-Ergebnis in die DB
   - Idempotent via `ON CONFLICT DO UPDATE`
   - Wächst automatisch bei jeder Analyse — DB wird immer größer

3. **`_check_address()` erweitert** — Neue Reihenfolge:
   - Stufe 0: Lokale DB (SEED_EXCHANGE + persistent gespeicherte Ergebnisse) ← NEU
   - Stufe 1: WalletExplorer API (+ persist bei Hit)
   - Stufe 2: Blockchair API (+ persist bei Hit)
   - Stufe 3: Downstream-Analyse (nur wenn `use_downstream=True`)

4. **`_lookup_address_exchange()` erweitert** — DB-Lookup als erste Stufe auch in der Downstream-Analyse
   - DB-Lookup verbraucht kein API-Call-Budget
   - Ergebnisse werden persistent gespeichert

### Testergebnisse (2026-03-22b)

- **TX `35abe6ba...` (Binance-Fall)**: `bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h` wird jetzt **sofort aus DB als Binance erkannt** ← Vorher: NICHT erkannt (offener Punkt aus 2026-03-21)
  - 2 Hops, 1x Binance, korrekt
- **TX `1f4bfff88...` (Huobi-Fall)**: 5 Hops, 2x Huobi — funktioniert weiterhin korrekt
  - Huobi-Adressen werden aus DB erkannt (kein WalletExplorer-Call nötig)

### Architektur: Exchange-Erkennung (komplett)

```
_check_address(addr)
  ↓
  0. Lokale DB (address_attributions) ← SCHNELL, GRATIS
  ↓ (kein Hit)
  1. WalletExplorer API → bei Hit: _db_persist_attribution()
  ↓ (kein Hit)
  2. Blockchair API → bei Hit: _db_persist_attribution()
  ↓ (kein Hit, use_downstream=True)
  3. Downstream-Analyse (Blockstream → Spending-TX → DB/API)
```

### Nächste Schritte (Meilenstein I)
- Weitere Transaktionen testen (verschiedene Exchanges, Edge Cases)
- Seed-Daten erweitern (mehr Adressen pro Exchange)
- WalletExplorer Cluster-Scraping evaluieren (Batch-Import ganzer Cluster)
- CIOH (Common Input Ownership Heuristic) für Phase 2 vorbereiten

---

## Session 2026-03-24 — BTC Exchange Intel Agent Integration (Meilenstein I, Stufe 1)

### Hintergrund

Parallel zu AIFinancialCrime wurde ein dedizierter **BTC Exchange Intel Agent** entwickelt:
- GitHub: https://github.com/ordinalsog-ctrl/btc-exchange-intel-agent
- Zweck: Zuverlässige, verifizierte Exchange-Adressen (L1-Qualität, keine Heuristiken)
- Snapshot Stand 2026-03-23: **1.761.245 Bitcoin-Adressen**, 26 Entities, 10.646 offizielle PoR-Adressen
- API läuft lokal auf `http://localhost:8080`
- Python-Client: `btc_exchange_intel_agent.client.ExchangeIntelClient`
- Datenbank: PostgreSQL + SQLite Snapshot, WalletExplorer Backfill läuft noch

### Was wurde gemacht

**`src/api/report_endpoint.py`** — Exchange Intel Agent als Stufe 1:

1. **`_exchange_intel_lookup(address)`** (NEU) — neue Lookup-Funktion
   - HTTP GET `http://localhost:8080/v1/address/{address}`
   - X-API-Key Header wenn `EXCHANGE_INTEL_API_KEY` gesetzt
   - 5 Sekunden Timeout (lokal, daher schnell)
   - `best_source_type` bestimmt Confidence: `official_por` / `seed` → L1, sonst → L2
   - Persistiert Treffer via `_db_persist_attribution(..., "EXCHANGE_INTEL")`

2. **`_check_address()` aktualisiert** — neue Stufenreihenfolge:
   - Stufe 0: Lokale DB (Seed + persistent gespeichert)
   - **Stufe 1: Exchange Intel Agent (1.76M Adressen) ← NEU**
   - Stufe 2: WalletExplorer API
   - Stufe 3: Blockchair API
   - Stufe 4: Downstream-Analyse (nur `use_downstream=True`)

3. **`_lookup_address_exchange()` aktualisiert** — Exchange Intel Agent nach DB, vor WalletExplorer

**`.env`** — Neue Variablen:
```
EXCHANGE_INTEL_API_URL=http://localhost:8080
EXCHANGE_INTEL_API_KEY=
```

**PostgreSQL** — `EXCHANGE_INTEL` als Attribution Source registriert:
- `source_key=EXCHANGE_INTEL`, `priority=2` (zwischen OFAC und SEED_EXCHANGE), `is_authoritative=TRUE`

### Neue Architektur: Exchange-Erkennung (komplett)

```
_check_address(addr)
  ↓
  0. Lokale DB (address_attributions) ← SCHNELL, GRATIS
  ↓ (kein Hit)
  1. Exchange Intel Agent (1.76M Adressen, lokal) ← NEU, SCHNELL
  ↓ (kein Hit)
  2. WalletExplorer API → bei Hit: _db_persist_attribution()
  ↓ (kein Hit)
  3. Blockchair API → bei Hit: _db_persist_attribution()
  ↓ (kein Hit, use_downstream=True)
  4. Downstream-Analyse (Blockstream → Spending-TX → DB/API)
```

### WalletExplorer Cluster-Evaluation

Recherche-Ergebnisse:
- WalletExplorer hat **kostenlosen, öffentlichen JSON-API** — kein API-Key nötig
- Endpoint: `/api/1/wallet-addresses?wallet=Binance.com&from=0&count=1000` — paginiert alle Adressen eines Clusters
- Binance-Cluster: **295.029 Adressen** (≈295 Seiten à 1000)
- Rate Limit: offiziell "keine Limits", historisch ~1 req/sec safe
- WalletExplorer ist Chainalysis-owned — Queries werden geloggt (für Strafverfolgung positiv)
- Datengüte: bis 94.85% True Positive Rate, <0.15% False Positive Rate (unabhängig evaluiert)
- Bundesrichter hat Chainalysis-Daten als gerichtsfest eingestuft (Bitcoin Fog Case)
- Der Exchange Intel Agent backfilled WalletExplorer bereits aktiv (`provider_backfill_we20.db`)
- → Kein eigenständiges Scraping nötig — der Agent übernimmt das

### Integration mit Exchange Intel Agent

Der Agent liefert via API:
- `GET /v1/address/{address}` — einzelne Adresse
- `POST /v1/lookup/batch` — Batch (empfohlen für mehrere Adressen gleichzeitig)
- `GET /v1/entity/{entity_name}/addresses` — alle Adressen einer Exchange
- `GET /v1/stats` — Datenbankstatistiken

Sobald der WalletExplorer-Backfill des Agents abgeschlossen ist, werden nahezu alle bekannten Exchange-Cluster-Adressen automatisch verfügbar — ohne dass AIFinancialCrime selbst scrapen muss.

### Nächste Schritte (Meilenstein I)
- Server testen mit dem neuen Lookup (Exchange Intel Agent muss laufen: `docker compose up -d`)
- Batch-Lookup für Hop-Analyse implementieren (alle Output-Adressen eines Hops auf einmal anfragen)
- Exchange Intel Agent API-Key setzen in `.env` (wenn AGENT_API_KEY konfiguriert)
- Weitere Transaktionen testen

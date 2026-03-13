# AIFinancialCrime — HANDOVER
> **Stand:** 2026-03-13 | Dieses Dokument in neuer Claude-Session uploaden → sofort weitermachen.

---

## Repo-Situation

**GitHub:** `https://github.com/ordinalsog-ctrl/AIFinancialCrime`

Das Repo enthält **zwei Codebasen** die parallel existieren:

### A) Bestehende Codebasis (bereits im Repo — nicht blind überschreiben)
- Bitcoin RPC → PostgreSQL Ingestion (`src/` — eigenes Schema)
- k-hop / entity-exposure / pattern-signals / risk-score API-Endpoints
- Evaluation Framework (gold_labels, regression_policy, data_quality_policy)
- `sql/001_init.sql` — eigenes Schema
- `scripts/run_*.sh` — Ingestion + Query Runner
- `docs/` — pattern_detection.md, risk_methodology.md, eval_framework.md

### B) Session-Codebasis (unsere Module — noch NICHT im Repo)
Alle Dateien aus den Claude-Sessions müssen in die Repo-Struktur integriert werden.
Das `sync_outputs.sh` Script legt sie an den richtigen Stellen ab **ohne** A) zu überschreiben.

---

## Ziel-Dateistruktur (Session-Module)

```
src/core/
  logging_config.py       ← Session 3
  metrics.py              ← Session 3

src/api/
  main.py                 ← Session 2 (SPA-Serving — ersetzt bestehende main.py nur wenn sicher)
  cases.py                ← Session 2
  health.py               ← Session 3
  auth.py                 ← Session 1

src/investigation/
  confidence_engine.py    ← Session 1
  attribution_db.py       ← Session 1
  report_generator.py     ← Session 2 (v3)
  pipeline.py             ← Session 2 (v2)
  peeling_chain.py        ← Session 1
  adapter.py              ← Session 1
  freeze_request.py       ← Session 1
  visualizer.py           ← Session 1 (v3)
  cio_cluster.py          ← Session 1
  bulk_ingest.py          ← Session 1
  exchange_contacts.py    ← Session 2
  serial_actor.py         ← Session 2
  graph_engine.py         ← Session 3
  change_heuristics.py    ← Session 3
  temporal_engine.py      ← Session 3

sql/
  000_migration_log.sql   ← Session 1 (ZUERST ausführen)
  002_attribution.sql     ← Session 1
  003_fraud_investigations.sql
  004_api_keys.sql
  005_cio_clusters.sql
  006_cases.sql           ← Session 2
  007_serial_actors.sql   ← Session 2

monitoring/
  prometheus.yml          ← Session 3
  alerts.yml              ← Session 3

scripts/
  setup_pi.sh             ← Session 2
  system_update.sh        ← Session 2
  e2e_test.py             ← Session 2
  sync_outputs.sh         ← Session 3

frontend/                 ← Session 2 (React/Vite, komplett neu)
```

---

## Architektur-Entscheidungen

| Entscheidung | Begründung |
|---|---|
| Bitcoin L1 only | Forensische Klarheit |
| Confidence L1–L4 regelbasiert, nie probabilistisch | Gerichtsverwertbarkeit |
| Exchange-Deposit-Adressen aus Serial-Actor-Check ausgeschlossen | Kein Täter-Merkmal |
| Web UI kommt zuletzt | Forensik-Fundament zuerst |
| Raspberry Pi 5 (16GB) + 1TB NVMe | Low-cost self-hosted |
| `txindex=1` in bitcoin.conf | Historische TX-Lookups |

## Confidence Framework

| Level | Kriterium |
|---|---|
| L1 | Direkter UTXO-Link — mathematisch bewiesen |
| L2 | Amount+Temporal ≤6h, Exchange-Attribution |
| L3 | Pattern observable, 6h–48h, Peeling |
| L4 | Heuristik (CIO), >48h, Amount-Mismatch >0.001 BTC |

---

## Session 3 — Was heute gebaut wurde

| Modul | Datei | Highlights |
|---|---|---|
| Structured Logging | `src/core/logging_config.py` | JSON, Correlation-IDs, `bind_investigation()`, FastAPI-Middleware |
| Health Endpoints | `src/api/health.py` | `/health` `/health/ready` `/health/db` `/health/blockchain` `/health/system` `/health/full` |
| Prometheus Metrics | `src/core/metrics.py` | Attribution-Hit-Rate, Investigation-Duration, System-Gauges, Request-Middleware |
| Prometheus Config | `monitoring/prometheus.yml` | API + Node Exporter + Postgres Exporter |
| Alert Rules | `monitoring/alerts.yml` | 10 Rules: Disk <10%, CPU >80°C, API-Error >5%, Hit-Rate <30% |
| Transaction Graph Engine | `src/investigation/graph_engine.py` | Fan-out, Fan-in, Layering, Re-Konvergenz, Dead-End Detection |
| Change Output Heuristics | `src/investigation/change_heuristics.py` | H1–H7: Script-Type, Round-Amount, Address-Reuse, BIP69, Positional |
| Temporal Pattern Engine | `src/investigation/temporal_engine.py` | Timezone-Inference, FATF-Window-Detection (24h), Velocity-Change |

---

## Nächste Schritte (Prio-Reihenfolge)

**1. Peeling Chain v2** — rekursiv, Richtungserkennung, Integration Graph + Change Heuristics
**2. Pipeline v3** — Graph + Change + Temporal einbinden, InvestigationResult erweitern
**3. Report Generator v4** — Graph-SVG-Sektion, Temporal-Analyse-Sektion, Change-Output-Markierung
**4. Bulk Import Phase 3** — WalletExplorer, OFAC SDN Auto-Sync, Attribution-Decay
**5. Redis Caching** — Blockstream TTL 1h, Attribution TTL 24h, Batch-UTXO 100 parallel
**6. Bitcoin Core RPC-Adapter** — nach Node-Sync
**7. Web UI** — letzter Schritt vor Launch

---

## Session fortsetzen

```
1. Neue Claude-Session öffnen
2. HANDOVER.md uploaden
3. "Lies HANDOVER.md, mach weiter mit Peeling Chain v2 + Pipeline v3"
```

---

*Zuletzt aktualisiert: 2026-03-13 — Session 3: Forensik-Fundament Phase 1+2*

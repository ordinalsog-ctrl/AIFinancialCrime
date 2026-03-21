# AIFinancialCrime — Entwicklungsjournal

## Projekt
Ziel: Forensisches Bitcoin-Analyse-Tool — gerichtsverwertbare PDFs + Exchange Freeze Requests
Repo: https://github.com/ordinalsog-ctrl/AIFinancialCrime
Stack: Python, PostgreSQL, FastAPI, HTML/CSS/JS
Starten: cd ~/AIFinancialCrime && lsof -ti:8000 | xargs kill -9 2>/dev/null && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
Browser: http://localhost:8000/intake

## Infrastruktur
Mac: PostgreSQL 16, DB aifinancialcrime, User aifc/aifc, FastAPI Port 8000
Pi 5: IP 192.168.178.93, SSH jonasweiss@192.168.178.93, Datadir /mnt/bitcoin_1tb/.bitcoin
Pi Status: bitcoin-cli -datadir=/mnt/bitcoin_1tb/.bitcoin getblockchaininfo
Pi Sync: Block 941470 (100%), txindex: true
Pi Reconnect: sudo mount /dev/sda1 /mnt/bitcoin_1tb && sudo systemctl start bitcoind

## API Keys (.env)
BLOCKCHAIR_API_KEY=PA__gj5kX0SKPwN1qv10LNnCzCKLnKAq
CHAINALYSIS_API_KEY=313a3ad73801d615d2326dd8cd8ac8a9d733fdf209bfa8fcc207da1646f2a092

## DB Schema
transactions: txid, block_height, fee_sats, vsize, first_seen
tx_outputs: txid, vout_index, address, amount_sats, spent_by_txid
tx_inputs: txid, vin_index, prev_txid, prev_vout, address, amount_sats
blocks: height, block_hash, timestamp

## Wichtige Dateien
main.py — FastAPI Entry Point
src/api/report_endpoint.py — EINZIGER API Endpoint
src/investigation/generate_case_report.py — EINZIGER PDF Generator
frontend/index.html — Browser Interface
scripts/generate_case_report.py — CLI Report Generator

## Architektur-Entscheidungen (NIEMALS AENDERN)
- generate_case_report.py ist die EINZIGE PDF-Quelle
- report_endpoint.py ist der EINZIGE API Endpoint fuer Reports
- Confidence L1-L4 rule-based, nie probabilistisch
- Bitcoin L1 only

## Confidence Framework
L1: Direkter UTXO-Link — mathematisch bewiesen
L2: Exchange-Attribution via WalletExplorer/Blockchair — forensisch belegt
L3: Muster/zeitlicher Zusammenhang — nicht im Report
L4: Spekulativ — nicht im Report

## API Flow
POST /api/intel/generate-report
  _trace_hops() via Pi-Node
  _check_address() WalletExplorer + Blockchair + Chainalysis
  _generate_pdf() via generate_case_report.py
  _generate_freeze_requests()
GET /api/intel/report-pdf/{case_id}
GET /api/intel/freeze-pdf/{case_id}/{exchange}

## Testfall Jonas Weiss
TX: 1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101
Block: 927547, 12.12.2025 08:44:52 UTC, 0.4124 BTC
Empfaenger: bc1qztlxu7flfclwfadlysrlv3lc5efnlrhxtwud72
Hop 1: 5e1e80ff (Split 0.20 + 0.21)
Hop 2: 578dbd7a (0.21 weiter)
Hop 3: df8dd002 (0.20 -> 1DLymHytX Intermediar)
Hop 4: 8d362e37 (0.21 -> 1B2opjpPP Intermediar)
Hop 5: Huobi 1AQLXAB6 L2
Hop 6: Poloniex 1LgW4RA5 L2

## Offene Punkte
1. Exchange-Erkennung: WalletExplorer erkennt 1AQLXAB6 (Huobi) und 1LgW4RA5 (Poloniex) — aber nur wenn Hops 3+4 komplett in DB
2. Transaktionsgraph: noch hardcoded auf Jonas Weiss Chain, muss dynamisch werden
3. Zeitstempel Hop 0: zeigt Block 0, muss echten Block-Timestamp aus DB laden
4. Zusammenfassung PDF: hardcoded Huobi+Poloniex, muss dynamisch aus erkannten Exchanges
5. PDF-Vorschau Browser: iframe leer, Workaround neues Tab
6. Blockchair Key: muss auf https://api.blockchair.com/premium aktiviert werden mit OTP per Email

## Sessions
Session 1-3 (2026-03-13): Projektstart, Schema, RPC Client
Session 4 (2026-03-20): Pi sync, erste TX ingested, erster Report 0 Hops
Session 5 (2026-03-20): Schema-Fixes, ingest_tx_by_txid, RPC Fallback, 2 Hops
Session 6 (2026-03-21): Cleanup, report_endpoint v2, TX-Picker HTML, CORS, Blockchair Key

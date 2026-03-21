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

## Offene Punkte
1. Exchange-Erkennung greift nicht weil Hops 3+4 nicht vollstaendig in DB verknuepft
2. Transaktionsgraph hardcoded — muss dynamisch aus HOPS gebaut werden
3. Zeitstempel Hop 0 zeigt Block 0 — muss aus DB geladen werden
4. PDF Zusammenfassung hardcoded Huobi+Poloniex — muss dynamisch
5. Blockchair Key noch nicht aktiviert — OTP per Email noetig

## Testfall Jonas Weiss
TX: 1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101
Block 927547, 12.12.2025, 0.4124 BTC
Hop 1: 5e1e80ff (Split)
Hop 2: 578dbd7a
Hop 3: df8dd002 -> 1DLymHytX (Intermediar)
Hop 4: 8d362e37 -> 1B2opjpPP (Intermediar)
Hop 5: Huobi 1AQLXAB6 L2
Hop 6: Poloniex 1LgW4RA5 L2

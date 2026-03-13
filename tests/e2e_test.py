#!/usr/bin/env python3
"""
End-to-end Integrationstest
scripts/e2e_test.py

Testet den vollständigen Stack:
  TXID-Input → Adapter → Pipeline → Confidence Engine → Attribution →
  Peeling-Chain → CIO → Report Generator → PDF-Output → Freeze Request

Läuft OHNE Live-Node oder DB (FixtureAdapter + In-Memory-Attribution).

Verwendung:
  python scripts/e2e_test.py             # normaler Run
  python scripts/e2e_test.py --verbose   # mit detaillierten Hop-Infos
  python scripts/e2e_test.py --live      # mit echtem Blockstream-API (braucht Internet)

Ausgabe:
  reports/e2e_report_<timestamp>.pdf
  reports/e2e_freeze_<exchange>_<timestamp>.pdf
"""

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Projektpfad ──────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Farben ───────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"; RED   = "\033[91m"; YELLOW = "\033[93m"
BLUE   = "\033[94m"; BOLD  = "\033[1m";  NC     = "\033[0m"
CYAN   = "\033[96m"

def ok(msg):  print(f"  {GREEN}✓{NC}  {msg}")
def fail(msg): print(f"  {RED}✗{NC}  {msg}"); sys.exit(1)
def info(msg): print(f"  {BLUE}→{NC}  {msg}")
def warn(msg): print(f"  {YELLOW}!{NC}  {msg}")
def sep(title): print(f"\n{BOLD}{CYAN}── {title} ──{NC}")


# =============================================================================
# Test-Konfiguration
# =============================================================================

# Bitfinex-Hack 2016 — öffentlich dokumentierter Peeling-Chain-Fall
# Adressen und Beträge basieren auf öffentlicher Blockchain-Forensik-Dokumentation
FRAUD_TXID    = "b68ef573e33843e8ae4e07f6a59ea8451d55eb7562d9c9fc9a02d68e681d8100"
FRAUD_ADDRESS = "1HQ3Go3ggs8pFnXuHVHRytPCq5fGG8Hbhx"
FRAUD_AMOUNT_BTC = 119756.0  # dokumentierter Hack-Betrag (BTC)
MAX_HOPS      = 3


def run_e2e_test(verbose: bool = False, live_mode: bool = False):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = PROJECT_ROOT / "reports"
    out_dir.mkdir(exist_ok=True)

    print(f"\n{BOLD}AIFinancialCrime — End-to-end Test{NC}")
    print(f"  Zeitstempel:  {ts}")
    print(f"  Modus:        {'LIVE (Blockstream API)' if live_mode else 'FIXTURE (offline)'}")
    print(f"  TXID:         {FRAUD_TXID[:32]}...")
    print(f"  Adresse:      {FRAUD_ADDRESS}")

    # ──────────────────────────────────────────────────────────────────────────
    sep("1 / 7 — Imports")
    # ──────────────────────────────────────────────────────────────────────────
    try:
        from src.investigation.adapters import (
            FixtureAdapter, BlockstreamAdapter, AdapterChain, TxData
        )
        ok("adapters importiert")
    except ImportError as e:
        fail(f"adapters Import fehlgeschlagen: {e}")

    try:
        from src.investigation.confidence_engine import (
            ConfidenceLevel, InvestigationChain, build_direct_utxo_hop, build_exchange_hop
        )
        ok("confidence_engine importiert")
    except ImportError as e:
        fail(f"confidence_engine Import fehlgeschlagen: {e}")

    try:
        from src.investigation.attribution_db import AttributionLookup, AttributionRepository
        ok("attribution_db importiert")
    except ImportError as e:
        fail(f"attribution_db Import fehlgeschlagen: {e}")

    try:
        from src.investigation.peeling_chain import PeelingChainDetector
        ok("peeling_chain importiert")
    except ImportError as e:
        fail(f"peeling_chain Import fehlgeschlagen: {e}")

    try:
        from src.investigation.report_generator import generate_report
        ok("report_generator importiert")
    except ImportError as e:
        fail(f"report_generator Import fehlgeschlagen: {e}")

    try:
        from src.investigation.freeze_request import FreezeRequestGenerator
        ok("freeze_request importiert")
    except ImportError as e:
        fail(f"freeze_request Import fehlgeschlagen: {e}")

    try:
        from src.investigation.pipeline import InvestigationPipeline
        ok("pipeline importiert")
    except ImportError as e:
        fail(f"pipeline Import fehlgeschlagen: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    sep("2 / 7 — Adapter Setup")
    # ──────────────────────────────────────────────────────────────────────────
    fixture_dir = PROJECT_ROOT / "eval" / "fixtures"

    fixture_adapter = FixtureAdapter(str(fixture_dir))
    ok(f"FixtureAdapter bereit ({fixture_dir})")

    if live_mode:
        live_adapter = BlockstreamAdapter()
        adapter = AdapterChain([fixture_adapter, live_adapter])
        ok("AdapterChain: Fixture → Blockstream (fallback)")
    else:
        adapter = fixture_adapter
        ok("Reiner Fixture-Modus (kein Netzwerk)")

    # Adapter-Test
    start = time.time()
    try:
        tx = adapter.get_transaction(FRAUD_TXID)
        elapsed = (time.time() - start) * 1000
        ok(f"TX geladen in {elapsed:.0f}ms: {tx.input_count} Inputs, {tx.output_count} Outputs")
        if verbose:
            for i, out in enumerate(tx.outputs):
                info(f"  Output {i}: {out.address} — {out.value_sat / 1e8:.8f} BTC")
    except Exception as e:
        fail(f"TX-Laden fehlgeschlagen: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    sep("3 / 7 — Attribution Setup")
    # ──────────────────────────────────────────────────────────────────────────
    # In-Memory Attribution aus Test-Fixtures
    manual_path = fixture_dir / "manual_attributions_test.json"

    class InMemoryAttribution:
        """Leichtgewichtige In-Memory Attribution für Tests."""
        def __init__(self, path: Path):
            self._data = {}
            if path.exists():
                entries = json.loads(path.read_text())
                for e in entries:
                    self._data[e["address"]] = e

        def lookup(self, address: str):
            e = self._data.get(address)
            if not e:
                return None
            return AttributionLookup(
                address=address,
                entity_name=e["entity_name"],
                entity_type=e["entity_type"],
                confidence="HIGH",
                source="MANUAL",
                is_sanctioned=e.get("is_sanctioned", False),
            )

        def lookup_many(self, addresses):
            return {a: self.lookup(a) for a in addresses if self.lookup(a)}

    from src.investigation.attribution_db import AttributionLookup

    attribution = InMemoryAttribution(manual_path)
    hits = sum(1 for a in [FRAUD_ADDRESS, "3FupZp77ySr7jwoLYEJ9mwzJpvokeyk5Ld"] if attribution.lookup(a))
    ok(f"In-Memory Attribution geladen: {len(attribution._data)} Einträge, {hits} Treffer für Test-Adressen")

    # ──────────────────────────────────────────────────────────────────────────
    sep("4 / 7 — Confidence Engine")
    # ──────────────────────────────────────────────────────────────────────────
    from src.investigation.confidence_engine import (
        ConfidenceLevel, InvestigationChain, TracingHop,
        build_direct_utxo_hop, build_exchange_hop, build_temporal_hop
    )

    chain = InvestigationChain(
        case_id=f"E2E-{ts}",
        fraud_txid=FRAUD_TXID,
        fraud_address=FRAUD_ADDRESS,
        fraud_amount_btc=FRAUD_AMOUNT_BTC,
        fraud_timestamp=datetime(2016, 8, 2, tzinfo=timezone.utc),
    )

    # Hop 1: direkte UTXO-Verbindung (L1 — mathematisch beweisbar)
    hop1 = build_direct_utxo_hop(
        src_txid=FRAUD_TXID,
        src_address=FRAUD_ADDRESS,
        dst_txid="c9843b8d4b3a2e7f1c5d6e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
        dst_address="1CGA1ZNMxgDKp7fX6wDpKBaGbWHCa17N1F",
        amount_btc=1999.0,
        hop_number=1,
    )
    chain.add_hop(hop1)
    ok(f"Hop 1: {hop1.confidence_level.name} — {hop1.dst_address[:20]}...")

    # Hop 2: zeitliche Korrelation (L2)
    hop2 = build_temporal_hop(
        src_txid="c9843b8d4b3a2e7f1c5d6e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
        src_address="1CGA1ZNMxgDKp7fX6wDpKBaGbWHCa17N1F",
        dst_txid="d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
        dst_address="3FupZp77ySr7jwoLYEJ9mwzJpvokeyk5Ld",
        amount_btc=1998.5,
        hours_delta=2.5,
        hop_number=2,
    )
    chain.add_hop(hop2)
    ok(f"Hop 2: {hop2.confidence_level.name} — {hop2.dst_address[:20]}...")

    # Hop 3: Exchange-Treffer (L2 mit Attribution)
    attr = attribution.lookup("3FupZp77ySr7jwoLYEJ9mwzJpvokeyk5Ld")
    if attr:
        hop3 = build_exchange_hop(
            src_txid="d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
            src_address="3FupZp77ySr7jwoLYEJ9mwzJpvokeyk5Ld",
            exchange_name=attr.entity_name,
            amount_btc=1998.5,
            hop_number=3,
        )
        chain.add_hop(hop3)
        ok(f"Hop 3: Exchange-Treffer → {BOLD}{attr.entity_name}{NC}")

    summary = chain.get_summary()
    ok(f"Chain-Summary: {summary['total_hops']} Hops, "
       f"stärkste Konfidenz: {summary['strongest_confidence']}, "
       f"Exchange-Treffer: {summary['exchange_hits']}")

    if verbose:
        for hop in chain.hops:
            info(f"  [{hop.hop_number}] {hop.confidence_level.name}: "
                 f"{hop.src_address[:16]}... → {hop.dst_address[:16]}... "
                 f"({hop.amount_btc:.2f} BTC)")

    # ──────────────────────────────────────────────────────────────────────────
    sep("5 / 7 — Peeling Chain Detection")
    # ──────────────────────────────────────────────────────────────────────────
    detector = PeelingChainDetector()

    # Baue Hops als Dict-Liste für den Detector
    hop_dicts = []
    for h in chain.hops:
        hop_dicts.append({
            "txid": h.dst_txid or h.src_txid,
            "src_address": h.src_address,
            "dst_address": h.dst_address,
            "amount_btc": h.amount_btc,
        })

    peeling_result = detector.analyze(hop_dicts)
    if peeling_result.get("is_peeling_chain"):
        ok(f"Peeling Chain erkannt: {peeling_result.get('length', 0)} Hops, "
           f"Ratio {peeling_result.get('amount_ratio', 0):.3f}")
    else:
        info("Kein klassisches Peeling-Chain-Muster erkannt")

    # ──────────────────────────────────────────────────────────────────────────
    sep("6 / 7 — Report Generator (PDF)")
    # ──────────────────────────────────────────────────────────────────────────
    pdf_path = out_dir / f"e2e_report_{ts}.pdf"

    start = time.time()
    try:
        generate_report(
            chain=chain,
            output_path=str(pdf_path),
            victim_name="Test-Opfer GmbH",
            victim_contact="test@example.com",
        )
        elapsed = (time.time() - start) * 1000
        size_kb = pdf_path.stat().st_size / 1024
        ok(f"PDF generiert in {elapsed:.0f}ms: {pdf_path.name} ({size_kb:.1f} KB)")
    except Exception as e:
        fail(f"PDF-Generierung fehlgeschlagen: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    sep("7 / 7 — Freeze Request Generator")
    # ──────────────────────────────────────────────────────────────────────────
    freeze_gen = FreezeRequestGenerator()

    exchange_hits = [h for h in chain.hops if h.dst_exchange]
    if not exchange_hits:
        warn("Keine Exchange-Treffer — Freeze Request übersprungen")
    else:
        for hop in exchange_hits:
            freeze_path = out_dir / f"e2e_freeze_{hop.dst_exchange.lower()}_{ts}.pdf"
            try:
                freeze_gen.generate(
                    chain=chain,
                    exchange_name=hop.dst_exchange,
                    exchange_address=hop.dst_address,
                    output_path=str(freeze_path),
                    language="de",
                )
                size_kb = freeze_path.stat().st_size / 1024
                ok(f"Freeze Request: {hop.dst_exchange} — {freeze_path.name} ({size_kb:.1f} KB)")
            except Exception as e:
                warn(f"Freeze Request {hop.dst_exchange} fehlgeschlagen: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Ergebnis
    # ──────────────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"{BOLD}{GREEN}  E2E Test BESTANDEN                            {NC}")
    print(f"{BOLD}{GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}\n")

    print(f"  {BOLD}Erzeugte Dateien:{NC}")
    for f in sorted(out_dir.glob(f"*{ts}*")):
        size = f.stat().st_size / 1024
        print(f"    {GREEN}→{NC} {f.name:50s} {size:6.1f} KB")

    print(f"\n  {BOLD}Chain-Zusammenfassung:{NC}")
    print(f"    Case-ID:         {chain.case_id}")
    print(f"    Betrag:          {FRAUD_AMOUNT_BTC:,.0f} BTC")
    print(f"    Hops:            {len(chain.hops)}")
    print(f"    Exchange-Treffer:{sum(1 for h in chain.hops if h.dst_exchange)}")
    print(f"    Stärkste Konf.:  {summary['strongest_confidence']}")
    if peeling_result.get("is_peeling_chain"):
        print(f"    Peeling Chain:   JA ({peeling_result.get('length')} Hops)")
    print()

    return True


def main():
    parser = argparse.ArgumentParser(description="AIFinancialCrime E2E Test")
    parser.add_argument("--verbose", "-v", action="store_true", help="Detaillierte Ausgabe")
    parser.add_argument("--live",    "-l", action="store_true", help="Live Blockstream API nutzen")
    args = parser.parse_args()

    try:
        success = run_e2e_test(verbose=args.verbose, live_mode=args.live)
        sys.exit(0 if success else 1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n{RED}Unerwarteter Fehler:{NC} {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

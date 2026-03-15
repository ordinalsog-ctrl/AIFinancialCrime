"""
AIFinancialCrime — Chainalysis Free Sanctions Screening API Adapter
====================================================================
Integriert die kostenlose Chainalysis Sanctions API für OFAC SDN Screening.

API: https://public.chainalysis.com/api/v1/address/<address>
Auth: X-API-Key Header
Rate Limit: 5000 Requests / 5 Minuten
Datenquelle: OFAC SDN List (US Department of Treasury)

Verwendung:
    adapter = ChainalysisAdapter()
    result = adapter.check_address("bc1q...")
    # → {"sanctioned": True, "identifications": [...], "confidence": "L1"}

Umgebungsvariable:
    CHAINALYSIS_API_KEY=<key>
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote

logger = logging.getLogger("aifc.chainalysis")

CHAINALYSIS_BASE     = "https://public.chainalysis.com"
CHAINALYSIS_API_KEY  = os.environ.get(
    "CHAINALYSIS_API_KEY",
    "313a3ad73801d615d2326dd8cd8ac8a9d733fdf209bfa8fcc207da1646f2a092"
)
RATE_LIMIT_SECONDS   = 0.07   # 5000 req / 5min = ~16/sec, konservativ ~14/sec


class ChainalysisAdapter:
    """
    Adapter für die Chainalysis Free Sanctions Screening API.

    Prüft Bitcoin-Adressen gegen OFAC SDN Liste.
    Gibt name, description, url der sanktionierten Entity zurück.

    Rate Limit: 5000 Requests / 5 Minuten
    Kein Caching erforderlich — API ist schnell und kostenlos.
    """

    def __init__(self, api_key: str = None):
        self._api_key = api_key or CHAINALYSIS_API_KEY
        self._last_request = 0.0
        if not self._api_key:
            raise ValueError("CHAINALYSIS_API_KEY nicht gesetzt")
        logger.info("chainalysis_adapter_init")

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_request
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)
        self._last_request = time.monotonic()

    def _get(self, path: str) -> Optional[dict]:
        """HTTP GET gegen Chainalysis API."""
        self._rate_limit()
        url = f"{CHAINALYSIS_BASE}{path}"
        try:
            req = Request(url, headers={
                "X-API-Key": self._api_key,
                "Accept":    "application/json",
                "User-Agent": "AIFinancialCrime/1.0",
            })
            with urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except HTTPError as e:
            if e.code == 403:
                logger.warning(f"chainalysis_rate_limited: {url}")
            elif e.code == 400:
                logger.warning(f"chainalysis_bad_request: {url}")
            else:
                logger.warning(f"chainalysis_http_error: {e.code} {url}")
            return None
        except URLError as e:
            logger.warning(f"chainalysis_url_error: {e} {url}")
            return None

    def check_address(self, address: str) -> dict:
        """
        Prüft eine Adresse gegen OFAC SDN Liste via Chainalysis API.

        Returns:
            {
                "address": str,
                "sanctioned": bool,
                "identifications": [...],   # Leer wenn nicht sanktioniert
                "confidence": "L1" | None,
                "source": "chainalysis",
            }

        identifications Objekt:
            {
                "category": "sanctions",
                "name": "SANCTIONS: OFAC SDN ...",
                "description": "...",
                "url": "https://home.treasury.gov/..."
            }
        """
        result = {
            "address":         address,
            "sanctioned":      False,
            "identifications": [],
            "confidence":      None,
            "source":          "chainalysis",
        }

        data = self._get(f"/api/v1/address/{quote(address)}")
        if data is None:
            return result

        identifications = data.get("identifications", [])

        if identifications:
            result["sanctioned"]      = True
            result["confidence"]      = "L1"
            result["identifications"] = identifications
            logger.info(
                f"chainalysis_hit: {address[:20]}... "
                f"name={identifications[0].get('name', '')[:50]}"
            )
        else:
            logger.debug(f"chainalysis_clean: {address[:20]}...")

        return result

    def batch_check(self, addresses: list[str]) -> dict[str, dict]:
        """
        Prüft mehrere Adressen nacheinander.
        Kein nativer Batch-Endpoint — sequentielle Einzelabfragen.

        Returns: {address: check_result}
        """
        results = {}
        total = len(addresses)
        hits  = 0

        for i, addr in enumerate(addresses):
            results[addr] = self.check_address(addr)
            if results[addr]["sanctioned"]:
                hits += 1
            if (i + 1) % 100 == 0:
                logger.info(f"chainalysis_batch_progress: {i+1}/{total}, hits={hits}")

        logger.info(f"chainalysis_batch_complete: total={total}, hits={hits}")
        return results

    def health_check(self) -> bool:
        """
        Prüft ob API erreichbar und Key gültig ist.
        Testet mit einer bekannten OFAC-Adresse.
        """
        # Lazarus Group OFAC-Adresse
        test_addr = "149w62rY42aZBox8fGcmqNsXUzSStKeq8C"
        try:
            data = self._get(f"/api/v1/address/{test_addr}")
            if data is None:
                return False
            # Sollte eine Identifikation zurückgeben
            ids = data.get("identifications", [])
            if ids:
                logger.info(f"chainalysis_health_ok: test hit confirmed ({ids[0].get('name','')})")
            else:
                logger.warning("chainalysis_health_warn: test address returned no identifications")
            return True
        except Exception as e:
            logger.error(f"chainalysis_health_failed: {e}")
            return False


# ---------------------------------------------------------------------------
# Integration in Attribution Pipeline
# ---------------------------------------------------------------------------

def enrich_address_with_chainalysis(address: str) -> dict:
    """
    Convenience-Funktion: Prüft Adresse gegen Chainalysis Sanctions API.
    Gibt strukturiertes Result zurück für Attribution-DB.

    Returns:
        {
            "address": str,
            "is_sanctioned": bool,
            "entity_name": str | None,
            "description": str | None,
            "ofac_url": str | None,
            "confidence": str | None,
            "source": "chainalysis",
        }
    """
    adapter = ChainalysisAdapter()
    result  = adapter.check_address(address)

    if not result["sanctioned"]:
        return {
            "address":      address,
            "is_sanctioned": False,
            "entity_name":  None,
            "description":  None,
            "ofac_url":     None,
            "confidence":   None,
            "source":       "chainalysis",
        }

    ids = result["identifications"][0] if result["identifications"] else {}
    return {
        "address":       address,
        "is_sanctioned": True,
        "entity_name":   ids.get("name"),
        "description":   ids.get("description"),
        "ofac_url":      ids.get("url"),
        "confidence":    "L1",
        "source":        "chainalysis",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    parser = argparse.ArgumentParser(description="Chainalysis Sanctions Adapter")
    parser.add_argument("--lookup",  metavar="ADDR",  help="Adresse prüfen")
    parser.add_argument("--health",  action="store_true", help="API Health Check")
    parser.add_argument("--batch",   metavar="FILE",  help="Adressen aus Datei prüfen")
    args = parser.parse_args()

    adapter = ChainalysisAdapter()

    if args.health:
        ok = adapter.health_check()
        print(f"API Status: {'✅ OK' if ok else '❌ Fehler'}")

    elif args.lookup:
        result = adapter.check_address(args.lookup)
        print(f"\nAdresse:    {result['address']}")
        print(f"Sanctioned: {result['sanctioned']}")
        if result["sanctioned"]:
            for ident in result["identifications"]:
                print(f"  Name:        {ident.get('name')}")
                print(f"  Description: {ident.get('description', '')[:100]}...")
                print(f"  URL:         {ident.get('url')}")

    elif args.batch:
        with open(args.batch) as f:
            addresses = [line.strip() for line in f if line.strip()]
        print(f"Prüfe {len(addresses)} Adressen...")
        results = adapter.batch_check(addresses)
        hits = [addr for addr, r in results.items() if r["sanctioned"]]
        print(f"\n✅ {len(hits)} sanktionierte Adressen gefunden:")
        for addr in hits:
            ids = results[addr]["identifications"]
            name = ids[0].get("name", "?") if ids else "?"
            print(f"  {addr} — {name}")

    else:
        parser.print_help()

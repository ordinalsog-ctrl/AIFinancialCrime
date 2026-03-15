"""
AIFinancialCrime — OpenSanctions API Adapter
=============================================
Integriert die OpenSanctions API für Sanctions Screening.

OpenSanctions ist ein Open-Data Projekt das folgende Listen vereint:
  - OFAC SDN (USA)
  - EU Consolidated Sanctions List
  - UN Security Council Sanctions
  - FATF High-Risk Jurisdictions
  - Interpol Red Notices
  - Nationale Listen (DE, UK, AU, etc.)
  - PEP-Datenbank (Politically Exposed Persons)

API: https://api.opensanctions.org (öffentlich, kein Key für Basic)
Docs: https://www.opensanctions.org/docs/api/

Endpoints die wir nutzen:
  GET /statements?prop=walletAddress&value=<addr>  → direkte Adress-Suche
  GET /search/default?q=<addr>&schema=CryptoWallet → Suche nach Wallet
  POST /match/default                               → Batch Entity Match

Verwendung:
    adapter = OpenSanctionsAdapter()

    # Einzelne Adresse prüfen
    result = adapter.check_address("1AQLXAB6aXSVbRMjbhSBudLf1kcsbWSEjg")

    # Batch-Check
    results = adapter.batch_check(["addr1", "addr2", ...])
"""

from __future__ import annotations

import json
import os
import time
import logging
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

logger = logging.getLogger("aifc.opensanctions")

OPENSANCTIONS_BASE = "https://api.opensanctions.org"
OPENSANCTIONS_DATASET = "default"  # Alle Quellen kombiniert

# Optional: Self-hosted instance
# OPENSANCTIONS_BASE = os.environ.get("OPENSANCTIONS_URL", "https://api.opensanctions.org")

RATE_LIMIT_SECONDS = 1.0  # Öffentliche API — konservativ


class OpenSanctionsAdapter:
    """
    Adapter für die OpenSanctions API.

    Prüft Bitcoin-Adressen gegen alle kombinierten Sanctions-Listen:
    OFAC, EU, UN, FATF, Interpol, nationale Listen.

    Kein API Key erforderlich für öffentliche Nutzung.
    Optional: Self-hosted Instanz via OPENSANCTIONS_URL Env-Variable.
    """

    def __init__(self):
        self._base = os.environ.get("OPENSANCTIONS_URL", OPENSANCTIONS_BASE)
        self._last_request = 0.0
        logger.info("opensanctions_adapter_init", base=self._base)

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_request
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)
        self._last_request = time.monotonic()

    def _get(self, path: str, params: dict = None) -> Optional[dict]:
        """HTTP GET gegen OpenSanctions API."""
        self._rate_limit()
        url = f"{self._base}{path}"
        if params:
            url += "?" + urlencode(params)
        try:
            req = Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "AIFinancialCrime/1.0",
            })
            with urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except (URLError, HTTPError) as e:
            logger.warning("opensanctions_request_failed", url=url, error=str(e))
            return None

    def _post(self, path: str, body: dict) -> Optional[dict]:
        """HTTP POST gegen OpenSanctions API."""
        self._rate_limit()
        url = f"{self._base}{path}"
        try:
            data = json.dumps(body).encode()
            req = Request(url, data=data, headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "AIFinancialCrime/1.0",
            })
            with urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except (URLError, HTTPError) as e:
            logger.warning("opensanctions_post_failed", url=url, error=str(e))
            return None

    def check_address(self, address: str) -> dict:
        """
        Prüft eine Bitcoin-Adresse gegen alle OpenSanctions-Listen.

        Strategie: Zwei parallele Suchen
          1. /statements — direkte Property-Suche nach walletAddress
          2. /search     — Freitext-Suche nach der Adresse

        Returns:
            {
                "address": str,
                "sanctioned": bool,
                "entities": [...],   # Gefundene Entities
                "sources": [...],    # Welche Listen haben getroffen
                "confidence": "L1"|"L2"|None,
            }
        """
        result = {
            "address":    address,
            "sanctioned": False,
            "entities":   [],
            "sources":    [],
            "confidence": None,
            "raw":        {},
        }

        # Methode 1: Statements-Suche (direkte Property-Übereinstimmung = L1)
        stmt_data = self._get("/statements", {
            "prop":   "walletAddress",
            "value":  address,
            "limit":  10,
        })

        if stmt_data and stmt_data.get("results"):
            result["sanctioned"] = True
            result["confidence"] = "L1"
            for stmt in stmt_data["results"]:
                entity_id = stmt.get("canonical_id") or stmt.get("entity_id")
                dataset   = stmt.get("dataset", "")
                if entity_id not in [e.get("id") for e in result["entities"]]:
                    # Entity-Details holen
                    entity = self._get_entity(entity_id)
                    if entity:
                        result["entities"].append(self._format_entity(entity, dataset))
                if dataset and dataset not in result["sources"]:
                    result["sources"].append(dataset)
            result["raw"]["statements"] = stmt_data
            logger.info("opensanctions_hit_statements",
                        address=address[:20], entities=len(result["entities"]))
            return result

        # Methode 2: Freitext-Suche (L2 — weniger präzise)
        search_data = self._get(f"/search/{OPENSANCTIONS_DATASET}", {
            "q":      address,
            "schema": "CryptoWallet",
            "limit":  5,
        })

        if search_data and search_data.get("results"):
            for entity in search_data["results"]:
                # Prüfe ob die Adresse wirklich in den Properties steht
                props = entity.get("properties", {})
                wallet_addrs = props.get("walletAddress", [])
                if address in wallet_addrs:
                    result["sanctioned"] = True
                    result["confidence"] = "L1"
                    result["entities"].append(self._format_entity(entity))
                elif search_data.get("total", {}).get("value", 0) > 0:
                    # Möglicher Treffer aber nicht exakt
                    result["confidence"] = "L2"
                    result["entities"].append(self._format_entity(entity))

            if result["entities"]:
                result["sanctioned"] = True
                result["raw"]["search"] = search_data

        logger.debug("opensanctions_checked",
                     address=address[:20],
                     sanctioned=result["sanctioned"],
                     confidence=result["confidence"])
        return result

    def _get_entity(self, entity_id: str) -> Optional[dict]:
        """Holt Entity-Details via ID."""
        if not entity_id:
            return None
        return self._get(f"/entities/{entity_id}")

    def _format_entity(self, entity: dict, dataset: str = "") -> dict:
        """Formatiert eine Entity für unsere Ausgabe."""
        props = entity.get("properties", {})
        return {
            "id":          entity.get("id", ""),
            "caption":     entity.get("caption", "Unknown"),
            "schema":      entity.get("schema", ""),
            "topics":      entity.get("topics", []),
            "datasets":    entity.get("datasets", [dataset] if dataset else []),
            "sanctions":   props.get("program", []),
            "aliases":     props.get("alias", []),
            "nationality": props.get("nationality", []),
            "addresses":   props.get("walletAddress", []),
            "url":         f"https://www.opensanctions.org/entities/{entity.get('id', '')}",
        }

    def batch_check(self, addresses: list[str]) -> dict[str, dict]:
        """
        Prüft mehrere Adressen.
        Nutzt POST /match für Batch-Lookup wenn möglich.

        Returns: {address: check_result}
        """
        results = {}

        # Versuche Batch via /match endpoint
        batch_result = self._batch_match(addresses)
        if batch_result:
            return batch_result

        # Fallback: Einzeln prüfen
        for addr in addresses:
            results[addr] = self.check_address(addr)
            time.sleep(0.5)

        return results

    def _batch_match(self, addresses: list[str]) -> Optional[dict[str, dict]]:
        """
        Batch-Match via POST /match/{dataset}.
        Sendet alle Adressen als CryptoWallet Entities.
        """
        if not addresses:
            return {}

        queries = {}
        for i, addr in enumerate(addresses):
            queries[f"addr_{i}"] = {
                "schema": "CryptoWallet",
                "properties": {
                    "walletAddress": [addr],
                },
            }

        response = self._post(f"/match/{OPENSANCTIONS_DATASET}", {
            "queries": queries,
        })

        if not response or "responses" not in response:
            return None

        results = {}
        addr_map = {f"addr_{i}": addr for i, addr in enumerate(addresses)}

        for key, match_result in response["responses"].items():
            addr = addr_map.get(key, key)
            results[addr] = {
                "address":    addr,
                "sanctioned": False,
                "entities":   [],
                "sources":    [],
                "confidence": None,
            }

            for result in match_result.get("results", []):
                score = result.get("score", 0)
                if score >= 0.9:  # Hohe Übereinstimmung
                    results[addr]["sanctioned"] = True
                    results[addr]["confidence"] = "L1" if score >= 0.99 else "L2"
                    results[addr]["entities"].append(
                        self._format_entity(result.get("entity", {}))
                    )

        logger.info("opensanctions_batch_complete",
                    total=len(addresses),
                    hits=sum(1 for r in results.values() if r["sanctioned"]))
        return results

    def health_check(self) -> bool:
        """Prüft ob API erreichbar ist."""
        try:
            data = self._get("/healthz")
            return data is not None
        except Exception:
            return False

    def get_datasets(self) -> list[str]:
        """Gibt alle verfügbaren Datensätze zurück."""
        data = self._get("/catalog")
        if not data:
            return []
        datasets = data.get("datasets", [])
        return [d.get("name", "") for d in datasets if d.get("name")]


# ---------------------------------------------------------------------------
# Integration in Attribution Pipeline
# ---------------------------------------------------------------------------

def enrich_address_with_sanctions(address: str) -> dict:
    """
    Convenience-Funktion: Prüft Adresse gegen OpenSanctions.
    Gibt strukturiertes Result zurück das direkt in Attribution-DB
    geschrieben werden kann.

    Returns:
        {
            "address": str,
            "is_sanctioned": bool,
            "entity_name": str,
            "sanction_programs": [...],
            "sources": [...],
            "confidence": str,
            "opensanctions_url": str,
        }
    """
    adapter = OpenSanctionsAdapter()
    result = adapter.check_address(address)

    if not result["sanctioned"] or not result["entities"]:
        return {
            "address":          address,
            "is_sanctioned":    False,
            "entity_name":      None,
            "sanction_programs": [],
            "sources":          [],
            "confidence":       None,
            "opensanctions_url": None,
        }

    entity = result["entities"][0]
    return {
        "address":           address,
        "is_sanctioned":     True,
        "entity_name":       entity["caption"],
        "sanction_programs": entity["sanctions"],
        "sources":           result["sources"] or entity["datasets"],
        "confidence":        result["confidence"],
        "opensanctions_url": entity["url"],
        "topics":            entity["topics"],
    }

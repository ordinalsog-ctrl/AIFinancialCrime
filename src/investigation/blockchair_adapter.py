"""
AIFinancialCrime — Blockchair Attribution Adapter
==================================================
Nutzt die Blockchair API als primäre Attribution-Quelle.

Aufruf-Reihenfolge im System:
  1. Blockchair API (Key) ← dieser Adapter
  2. WalletExplorer
  3. Eigene DB
  4. unbekannt

Konfiguration:
    BLOCKCHAIR_API_KEY=... in .env

Verwendung:
    adapter = BlockchairAttributionAdapter()
    result = adapter.lookup("1AQLXAB6aXSVbRMjbhSBudLf1kcsbWSEjg")
    # → {"label": "Huobi", "confidence": "L2", "source": "blockchair"}
"""

from __future__ import annotations

import os
import json
import time
import logging
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger("aifc.blockchair")

BLOCKCHAIR_BASE = "https://api.blockchair.com/bitcoin/dashboards/address"
RATE_LIMIT_SECONDS = 0.5  # 2 req/s mit Key


class BlockchairAttributionAdapter:
    """
    Blockchair API Adapter für Exchange-Attribution.
    Fail-open: gibt None zurück wenn Key fehlt oder API nicht erreichbar.
    """

    def __init__(self):
        self._key = os.environ.get("BLOCKCHAIR_API_KEY")
        self._last_request = 0.0
        if not self._key:
            logger.warning("BLOCKCHAIR_API_KEY nicht gesetzt — Adapter deaktiviert")

    @property
    def available(self) -> bool:
        return bool(self._key)

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_request
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)
        self._last_request = time.monotonic()

    def lookup(self, address: str) -> Optional[dict]:
        """
        Schlägt eine Adresse in Blockchair nach.

        Returns:
            {
                "label": str,
                "entity_type": str,
                "confidence": "L2",
                "source": "blockchair",
                "tx_count": int,
                "volume_btc": float,
            }
            oder None wenn nicht gefunden / kein Label.
        """
        if not self._key:
            return None

        self._rate_limit()

        url = f"{BLOCKCHAIR_BASE}/{address}?transaction_details=false&key={self._key}"
        try:
            req = Request(url, headers={"User-Agent": "AIFinancialCrime/1.0"})
            with urlopen(req, timeout=10) as r:
                data = json.loads(r.read())

            addr_data = data.get("data", {}).get(address, {}).get("address", {})
            tag = addr_data.get("tag")

            if not tag:
                return None

            return {
                "label":       tag,
                "entity_type": "exchange",
                "confidence":  "L2",
                "source":      "blockchair",
                "tx_count":    addr_data.get("transaction_count", 0),
                "volume_btc":  addr_data.get("received", 0) / 1e8,
            }

        except (URLError, HTTPError) as e:
            logger.warning("blockchair_lookup_failed", address=address[:20], error=str(e))
            return None

    def batch_lookup(self, addresses: list[str]) -> dict[str, Optional[dict]]:
        """
        Batch-Lookup für mehrere Adressen.
        Returns: {address: result_or_none}
        """
        results = {}
        for addr in addresses:
            results[addr] = self.lookup(addr)
        return results


# ---------------------------------------------------------------------------
# Attribution Pipeline — kombiniert alle Quellen
# ---------------------------------------------------------------------------

def lookup_attribution(address: str, repo=None) -> dict:
    """
    Kombinierte Attribution-Suche über alle Quellen.
    Gibt bestes verfügbares Ergebnis zurück.

    Reihenfolge:
      1. Blockchair API
      2. WalletExplorer
      3. Eigene DB (repo)
      4. unbekannt
    """
    # 1. Blockchair
    bc = BlockchairAttributionAdapter()
    if bc.available:
        result = bc.lookup(address)
        if result:
            logger.info("attribution_found", source="blockchair",
                        address=address[:20], label=result["label"])
            return result

    # 2. WalletExplorer
    we_result = _walletexplorer_lookup(address)
    if we_result:
        logger.info("attribution_found", source="walletexplorer",
                    address=address[:20], label=we_result["label"])
        return we_result

    # 3. Eigene DB
    if repo:
        try:
            rec = repo.lookup_best(address)
            if rec:
                return {
                    "label":       rec.entity_name,
                    "entity_type": rec.entity_type,
                    "confidence":  "L1" if rec.source_confidence_level >= 80 else "L2",
                    "source":      rec.source_key,
                    "tx_count":    None,
                    "volume_btc":  None,
                }
        except Exception as e:
            logger.debug("db_lookup_failed", error=str(e))

    return {
        "label":       None,
        "entity_type": "unknown",
        "confidence":  None,
        "source":      None,
        "tx_count":    None,
        "volume_btc":  None,
    }


def _walletexplorer_lookup(address: str) -> Optional[dict]:
    """WalletExplorer Fallback."""
    try:
        url = (f"https://www.walletexplorer.com/api/1/address"
               f"?address={address}&from=0&count=1&caller=aifc")
        req = Request(url, headers={"User-Agent": "AIFinancialCrime/1.0"})
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read())

        if not data.get("found") or not data.get("label"):
            return None

        return {
            "label":       data["label"],
            "entity_type": "exchange",
            "confidence":  "L2",
            "source":      "walletexplorer",
            "wallet_id":   data.get("wallet_id"),
            "tx_count":    data.get("txs_count"),
            "volume_btc":  None,
        }
    except Exception:
        return None

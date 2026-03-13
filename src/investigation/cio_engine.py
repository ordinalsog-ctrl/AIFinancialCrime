"""
CIO Cluster Engine — Common Input Ownership Heuristik

Kernprinzip:
    Wenn eine Bitcoin-Transaktion mehrere Inputs von verschiedenen Adressen
    hat, kontrolliert mit hoher Wahrscheinlichkeit eine einzige Entität alle
    diese Adressen (weil man für jeden Input den privaten Schlüssel braucht).

    Das ist die Common Input Ownership (CIO) Heuristik — die grundlegendste
    und zuverlässigste on-chain Clustering-Methode.

Ausnahmen (false-positive Risiko):
    - CoinJoin-Transaktionen (viele Inputs, koordinierter Mix)
    - Wallet-Software die absichtlich mehrere Wallets kombiniert
    → Wir markieren diese Fälle mit niedrigerem Konfidenz-Level

Architektur:
    CioEngine          — Hauptklasse, koordiniert alles
    ClusterStore       — PostgreSQL-Backend (Union-Find über DB)
    CioAnalyser        — analysiert eine TX und merged Cluster
    ExchangeDepositDB  — Modul B: bekannte Exchange-Adressen

Verwendung:
    engine = CioEngine(db_conn, blockchain_adapter)

    # Einzelne TX analysieren (z.B. während Investigation)
    result = engine.process_tx(txid)

    # Adresse attributieren
    attr = engine.attribute_address("1ABC...")

    # Nach abgeschlossener Investigation: Exchange-Hit speichern
    engine.confirm_exchange_hit("1ABC...", "Binance", txid="...")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------

@dataclass
class CioCluster:
    cluster_id: int
    address_count: int
    entity_name: Optional[str]
    entity_type: Optional[str]
    attribution_source: Optional[str]
    confidence_level: Optional[int]
    attributed_at: Optional[datetime]

    @property
    def is_attributed(self) -> bool:
        return self.entity_name is not None

    @property
    def is_exchange(self) -> bool:
        return self.entity_type == "EXCHANGE"


@dataclass
class CioTxResult:
    """Ergebnis der Analyse einer einzelnen TX."""
    txid: str
    input_addresses: list[str]
    cluster_id: Optional[int]           # None wenn < 2 Adressen
    was_merged: bool                    # True wenn Cluster zusammengeführt
    is_likely_coinjoin: bool
    attribution: Optional[CioCluster]  # Falls Cluster bereits attribuiert


@dataclass
class AddressAttribution:
    """Vollständige Attribution einer Adresse inkl. Herleitung."""
    address: str
    found: bool
    # Direkte Attribution (aus address_attributions Tabelle)
    direct_entity: Optional[str] = None
    direct_source: Optional[str] = None
    direct_confidence: Optional[int] = None
    # CIO-Cluster Attribution
    cluster_id: Optional[int] = None
    cluster_entity: Optional[str] = None
    cluster_entity_type: Optional[str] = None
    cluster_confidence: Optional[int] = None  # immer +1 zu Quelle
    cluster_size: Optional[int] = None
    cluster_source: Optional[str] = None
    # Bestes Ergebnis (priorisiert direkte Attribution)
    best_entity: Optional[str] = None
    best_entity_type: Optional[str] = None
    best_confidence: Optional[int] = None
    best_source: Optional[str] = None
    attribution_method: Optional[str] = None  # 'DIRECT' | 'CIO_CLUSTER'

    def to_report_dict(self) -> dict:
        return {
            "address": self.address,
            "found": self.found,
            "entity": self.best_entity,
            "entity_type": self.best_entity_type,
            "confidence_level": self.best_confidence,
            "source": self.best_source,
            "method": self.attribution_method,
            "cluster_id": self.cluster_id,
            "cluster_size": self.cluster_size,
        }


# ---------------------------------------------------------------------------
# CoinJoin-Erkennung
# ---------------------------------------------------------------------------

COINJOIN_MIN_INPUTS  = 5    # Mindestanzahl Inputs um CoinJoin zu vermuten
COINJOIN_EQUAL_RATIO = 0.8  # 80%+ gleiche Output-Beträge → wahrscheinlich CoinJoin

def _is_likely_coinjoin(input_addresses: list[str], output_values: list[int]) -> bool:
    """
    Einfache Heuristik zur CoinJoin-Erkennung.
    CoinJoin: viele Inputs von verschiedenen Parteien, gleiche Output-Beträge.
    Falsch-Positiv-Rate ist hier unkritisch — wir senken nur den Konfidenz-Level.
    """
    if len(input_addresses) < COINJOIN_MIN_INPUTS:
        return False
    if len(set(input_addresses)) < COINJOIN_MIN_INPUTS:
        return False  # Gleiche Adresse mehrfach = kein CoinJoin
    if not output_values:
        return False
    # Prüfe ob die meisten Outputs denselben Betrag haben
    from collections import Counter
    counts = Counter(output_values)
    most_common_count = counts.most_common(1)[0][1]
    return (most_common_count / len(output_values)) >= COINJOIN_EQUAL_RATIO


# ---------------------------------------------------------------------------
# ClusterStore — PostgreSQL Union-Find
# ---------------------------------------------------------------------------

class ClusterStore:
    """
    Verwaltet CIO-Cluster in PostgreSQL.
    Implementiert Union-Find ohne rekursive Pfadkompression —
    stattdessen flache Tabelle: jede Adresse zeigt direkt auf cluster_id.
    Merge = UPDATE alle Adressen des kleineren Clusters auf die ID des größeren.
    """

    def __init__(self, conn):
        self._conn = conn

    def get_cluster_id(self, address: str) -> Optional[int]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT cluster_id FROM cio_address_cluster WHERE address = %s",
                (address,)
            )
            row = cur.fetchone()
            return row[0] if row else None

    def get_cluster(self, cluster_id: int) -> Optional[CioCluster]:
        with self._conn.cursor() as cur:
            cur.execute("""
                SELECT cluster_id, address_count, entity_name, entity_type,
                       attribution_source, confidence_level, attributed_at
                FROM cio_clusters WHERE cluster_id = %s
            """, (cluster_id,))
            row = cur.fetchone()
            if not row:
                return None
            return CioCluster(
                cluster_id=row[0], address_count=row[1],
                entity_name=row[2], entity_type=row[3],
                attribution_source=row[4], confidence_level=row[5],
                attributed_at=row[6],
            )

    def get_cluster_for_address(self, address: str) -> Optional[CioCluster]:
        cid = self.get_cluster_id(address)
        return self.get_cluster(cid) if cid else None

    def get_cluster_addresses(self, cluster_id: int, limit: int = 1000) -> list[str]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT address FROM cio_address_cluster WHERE cluster_id = %s LIMIT %s",
                (cluster_id, limit)
            )
            return [r[0] for r in cur.fetchall()]

    def create_cluster(self, address: str, seed_txid: Optional[str] = None) -> int:
        """Erstellt einen neuen Cluster mit einer einzelnen Adresse."""
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO cio_clusters (address_count) VALUES (1) RETURNING cluster_id"
            )
            cluster_id = cur.fetchone()[0]
            cur.execute(
                """INSERT INTO cio_address_cluster (address, cluster_id, first_seen_txid)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (address) DO NOTHING""",
                (address, cluster_id, seed_txid)
            )
        self._conn.commit()
        return cluster_id

    def ensure_cluster(self, address: str, seed_txid: Optional[str] = None) -> int:
        """Gibt bestehende cluster_id zurück oder erstellt einen neuen Cluster."""
        cid = self.get_cluster_id(address)
        if cid is not None:
            return cid
        return self.create_cluster(address, seed_txid)

    def merge(self, cluster_ids: list[int], txid: str, all_addresses: list[str]) -> int:
        """
        Merged mehrere Cluster zu einem.
        Strategie: größter Cluster gewinnt (minimiert UPDATE-Volumen).
        Gibt die finale cluster_id zurück.
        """
        if len(cluster_ids) == 0:
            raise ValueError("merge() braucht mindestens einen Cluster")
        if len(cluster_ids) == 1:
            return cluster_ids[0]

        with self._conn.cursor() as cur:
            # Größten Cluster finden
            cur.execute(
                "SELECT cluster_id, address_count FROM cio_clusters "
                "WHERE cluster_id = ANY(%s) ORDER BY address_count DESC LIMIT 1",
                (cluster_ids,)
            )
            winner_id, _ = cur.fetchone()
            losers = [c for c in cluster_ids if c != winner_id]

            # Alle Adressen der Loser-Cluster auf Winner umschreiben
            cur.execute(
                "UPDATE cio_address_cluster SET cluster_id = %s "
                "WHERE cluster_id = ANY(%s)",
                (winner_id, losers)
            )

            # Adresszahl im Winner aktualisieren
            cur.execute(
                "UPDATE cio_clusters SET "
                "  address_count = (SELECT COUNT(*) FROM cio_address_cluster WHERE cluster_id = %s),"
                "  updated_at = NOW() "
                "WHERE cluster_id = %s",
                (winner_id, winner_id)
            )

            # Loser-Cluster löschen
            cur.execute(
                "DELETE FROM cio_clusters WHERE cluster_id = ANY(%s)",
                (losers,)
            )

            # Evidence speichern
            cur.execute(
                """INSERT INTO cio_evidence (txid, cluster_id, addresses_merged, input_count)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (txid, cluster_id) DO NOTHING""",
                (txid, winner_id, all_addresses, len(all_addresses))
            )

        self._conn.commit()
        logger.debug(f"CIO merge: {cluster_ids} → {winner_id} (tx={txid[:16]}…)")
        return winner_id

    def label_cluster(
        self,
        cluster_id: int,
        entity_name: str,
        entity_type: str,
        source: str,
        confidence_level: int,
    ) -> None:
        """Setzt oder überschreibt die Attribution eines Clusters."""
        with self._conn.cursor() as cur:
            cur.execute("""
                UPDATE cio_clusters SET
                    entity_name       = %s,
                    entity_type       = %s,
                    attribution_source = %s,
                    confidence_level  = %s,
                    attributed_at     = NOW(),
                    updated_at        = NOW()
                WHERE cluster_id = %s
            """, (entity_name, entity_type, source, confidence_level, cluster_id))
        self._conn.commit()
        logger.info(
            f"CIO: Cluster {cluster_id} labelled as {entity_name} "
            f"({entity_type}) via {source}"
        )

    def propagate_label_from_address(self, address: str) -> bool:
        """
        Wenn 'address' direkt attribuiert ist (address_attributions),
        propagiert die Attribution auf den gesamten Cluster.
        Gibt True zurück wenn etwas propagiert wurde.
        """
        with self._conn.cursor() as cur:
            # Direkte Attribution der Adresse holen
            cur.execute("""
                SELECT aa.entity_name, aa.entity_type, s.source_key, aa.confidence_level
                FROM address_attributions aa
                JOIN attribution_sources s ON aa.source_id = s.source_id
                WHERE aa.address = %s
                ORDER BY s.priority ASC
                LIMIT 1
            """, (address,))
            row = cur.fetchone()
            if not row:
                return False
            entity_name, entity_type, source_key, confidence = row

            # Cluster der Adresse holen
            cur.execute(
                "SELECT cluster_id FROM cio_address_cluster WHERE address = %s",
                (address,)
            )
            row2 = cur.fetchone()
            if not row2:
                return False
            cluster_id = row2[0]

            # Nur propagieren wenn Cluster noch nicht (besser) attribuiert
            cur.execute(
                "SELECT confidence_level FROM cio_clusters WHERE cluster_id = %s",
                (cluster_id,)
            )
            existing = cur.fetchone()
            if existing and existing[0] is not None and existing[0] <= confidence:
                return False  # Bereits gleich gut oder besser attribuiert

        self.label_cluster(
            cluster_id, entity_name, entity_type,
            source=f"PROPAGATED_FROM_{source_key}",
            confidence_level=confidence,
        )
        return True


# ---------------------------------------------------------------------------
# CIO Analyser — analysiert eine TX und verwaltet Cluster
# ---------------------------------------------------------------------------

class CioAnalyser:
    """
    Analysiert eine TX:
    1. Alle Input-Adressen extrahieren
    2. CoinJoin prüfen
    3. Cluster mergen
    4. Attribution propagieren falls ein Cluster bereits bekannt
    """

    def __init__(self, store: ClusterStore):
        self._store = store

    def process_tx(
        self,
        txid: str,
        input_addresses: list[str],
        output_values: Optional[list[int]] = None,
    ) -> CioTxResult:
        """
        Verarbeitet eine TX.
        input_addresses: alle Adressen die als Input in dieser TX vorkommen.
        output_values:   Satoshi-Beträge der Outputs (für CoinJoin-Erkennung).
        """
        # Deduplizieren (selbe Adresse kann mehrfach Input sein)
        unique_addrs = list(dict.fromkeys(a for a in input_addresses if a))

        if len(unique_addrs) < 2:
            # Nur eine Adresse → kein CIO-Signal, aber Cluster sicherstellen
            if unique_addrs:
                self._store.ensure_cluster(unique_addrs[0], seed_txid=txid)
            return CioTxResult(
                txid=txid, input_addresses=unique_addrs,
                cluster_id=None, was_merged=False,
                is_likely_coinjoin=False, attribution=None,
            )

        # CoinJoin prüfen
        is_cj = _is_likely_coinjoin(unique_addrs, output_values or [])
        if is_cj:
            logger.info(
                f"CIO: TX {txid[:16]}… wahrscheinlich CoinJoin "
                f"({len(unique_addrs)} Inputs) — kein Merge"
            )
            # Cluster für jede Adresse sicherstellen, aber NICHT mergen
            for addr in unique_addrs:
                self._store.ensure_cluster(addr, seed_txid=txid)
            return CioTxResult(
                txid=txid, input_addresses=unique_addrs,
                cluster_id=None, was_merged=False,
                is_likely_coinjoin=True, attribution=None,
            )

        # Cluster für alle Adressen holen/erstellen
        cluster_ids = []
        for addr in unique_addrs:
            cid = self._store.ensure_cluster(addr, seed_txid=txid)
            cluster_ids.append(cid)

        unique_cluster_ids = list(dict.fromkeys(cluster_ids))
        was_merged = len(unique_cluster_ids) > 1

        # Mergen
        final_cluster_id = self._store.merge(unique_cluster_ids, txid, unique_addrs)

        # Attribution propagieren: falls eine der Adressen bekannt ist,
        # auf gesamten Cluster ausweiten
        for addr in unique_addrs:
            if self._store.propagate_label_from_address(addr):
                logger.info(
                    f"CIO: Cluster {final_cluster_id} Attribution propagiert "
                    f"via Adresse {addr[:20]}…"
                )
                break

        cluster = self._store.get_cluster(final_cluster_id)

        return CioTxResult(
            txid=txid,
            input_addresses=unique_addrs,
            cluster_id=final_cluster_id,
            was_merged=was_merged,
            is_likely_coinjoin=False,
            attribution=cluster if (cluster and cluster.is_attributed) else None,
        )


# ---------------------------------------------------------------------------
# Exchange Deposit DB — Modul B
# ---------------------------------------------------------------------------

class ExchangeDepositDB:
    """
    Sammelt und verwaltet bekannte Exchange-Deposit-Adressen.

    Quellen:
      1. Blockchair Labels API (kostenlos, keine Auth)
      2. GitHub-Community-Listen (einmalig importiert)
      3. Bestätigte Funde aus eigenen Untersuchungen (automatisch)

    Alle Einträge landen in address_attributions mit Source-Priority 3–7.
    """

    BLOCKCHAIR_API = "https://api.blockchair.com/bitcoin/addresses/balances"
    BLOCKCHAIR_LABELS = "https://api.blockchair.com/bitcoin/addresses?a=address,type,scripthash_type&q=type(pubkeyhash,scripthash)"

    # Bekannte Exchange-Deposit-Präfixe / Muster
    # Quelle: öffentliche Blockchain-Explorer Tags, manuell kuriert
    KNOWN_EXCHANGE_LABELS: dict[str, tuple[str, str]] = {
        # (display_name, entity_type)
        "binance":       ("Binance",       "EXCHANGE"),
        "coinbase":      ("Coinbase",      "EXCHANGE"),
        "kraken":        ("Kraken",        "EXCHANGE"),
        "bitfinex":      ("Bitfinex",      "EXCHANGE"),
        "bitstamp":      ("Bitstamp",      "EXCHANGE"),
        "okx":           ("OKX",           "EXCHANGE"),
        "okex":          ("OKX",           "EXCHANGE"),
        "huobi":         ("Huobi",         "EXCHANGE"),
        "kucoin":        ("KuCoin",        "EXCHANGE"),
        "bybit":         ("Bybit",         "EXCHANGE"),
        "gemini":        ("Gemini",        "EXCHANGE"),
        "crypto.com":    ("Crypto.com",    "EXCHANGE"),
        "gate.io":       ("Gate.io",       "EXCHANGE"),
        "bittrex":       ("Bittrex",       "EXCHANGE"),
        "poloniex":      ("Poloniex",      "EXCHANGE"),
        "bitmex":        ("BitMEX",        "EXCHANGE"),
        "deribit":       ("Deribit",       "EXCHANGE"),
        "blockchain.com":("Blockchain.com","EXCHANGE"),
        "electrum":      ("Electrum",      "OTHER"),
        "wasabi":        ("Wasabi Wallet",  "MIXER"),
        "samourai":      ("Samourai Wallet","MIXER"),
        "chipmixer":     ("ChipMixer",      "MIXER"),
        "helix":         ("Helix Mixer",    "MIXER"),
        "bestmixer":     ("BestMixer",      "MIXER"),
        "hydra":         ("Hydra Market",   "DARKNET"),
        "alphabay":      ("AlphaBay",       "DARKNET"),
        "silk road":     ("Silk Road",      "DARKNET"),
    }

    def __init__(self, conn):
        self._conn = conn

    def lookup_blockchair(self, address: str) -> Optional[dict]:
        """
        Fragt Blockchair Labels für eine einzelne Adresse ab.
        Kostenlos, kein API-Key benötigt für Basis-Lookups.
        Rate limit: ~1 req/sec.
        """
        import time
        import json
        from urllib.request import urlopen, Request
        from urllib.error import URLError

        url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}?privacy-o-meter=true"
        try:
            time.sleep(1.0)  # Rate limiting
            req = Request(url, headers={"User-Agent": "AIFinancialCrime/1.0"})
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
        except (URLError, json.JSONDecodeError) as e:
            logger.warning(f"Blockchair lookup failed for {address}: {e}")
            return None

        if "data" not in data or address not in data["data"]:
            return None

        addr_data = data["data"][address]
        address_info = addr_data.get("address", {})

        # Blockchair liefert manchmal ein "type" Label
        label = address_info.get("type", "") or ""

        # Kontext-Tags aus Transaction-Daten
        context = data.get("context", {})

        return {
            "address": address,
            "blockchair_type": label,
            "transaction_count": address_info.get("transaction_count", 0),
            "balance_sat": address_info.get("balance", 0),
            "received_sat": address_info.get("received", 0),
            "first_seen_receiving": address_info.get("first_seen_receiving"),
            "last_seen_receiving": address_info.get("last_seen_receiving"),
        }

    def _match_label_to_entity(self, label: str) -> Optional[tuple[str, str]]:
        """Versucht ein Label einem bekannten Exchange zuzuordnen."""
        label_lower = label.lower()
        for keyword, (name, etype) in self.KNOWN_EXCHANGE_LABELS.items():
            if keyword in label_lower:
                return name, etype
        return None

    def store_address(
        self,
        address: str,
        entity_name: str,
        entity_type: str,
        source_key: str,
        confidence_level: int,
        raw_data: Optional[dict] = None,
    ) -> bool:
        """
        Speichert eine attributierte Adresse in address_attributions.
        Idempotent — überschreibt nur wenn neue Source höhere Priorität hat.
        Gibt True zurück wenn neu gespeichert oder aktualisiert.
        """
        with self._conn.cursor() as cur:
            # Source-ID holen
            cur.execute(
                "SELECT source_id, priority FROM attribution_sources WHERE source_key = %s",
                (source_key,)
            )
            row = cur.fetchone()
            if not row:
                logger.error(f"Unknown source_key: {source_key}")
                return False
            source_id, priority = row

            cur.execute("""
                INSERT INTO address_attributions
                    (address, source_id, entity_name, entity_type,
                     confidence_level, is_sanctioned, raw_source_data,
                     first_seen_at, last_updated_at)
                VALUES
                    (%s, %s, %s, %s, %s, FALSE, %s, NOW(), NOW())
                ON CONFLICT (address, source_id) DO UPDATE SET
                    entity_name      = EXCLUDED.entity_name,
                    entity_type      = EXCLUDED.entity_type,
                    confidence_level = EXCLUDED.confidence_level,
                    raw_source_data  = EXCLUDED.raw_source_data,
                    last_updated_at  = NOW()
                WHERE address_attributions.confidence_level > EXCLUDED.confidence_level
                   OR address_attributions.entity_name IS NULL
            """, (
                address, source_id, entity_name, entity_type,
                confidence_level,
                __import__("json").dumps(raw_data) if raw_data else None,
            ))
            affected = cur.rowcount
        self._conn.commit()
        return affected > 0

    def confirm_investigation_hit(
        self,
        address: str,
        entity_name: str,
        entity_type: str,
        case_id: str,
        txid: Optional[str] = None,
    ) -> None:
        """
        Speichert einen bestätigten Fund aus einer Untersuchung.
        Source: INVESTIGATION — höchste Eigenprioritäts-Stufe (Priority 3, L1).
        Wird automatisch aufgerufen wenn ein Exchange-Hit im Report bestätigt wird.
        """
        raw = {"case_id": case_id, "confirmed_txid": txid}
        stored = self.store_address(
            address=address,
            entity_name=entity_name,
            entity_type=entity_type,
            source_key="INVESTIGATION",
            confidence_level=1,  # L1 — direkt bestätigt
            raw_data=raw,
        )
        if stored:
            logger.info(
                f"ExchangeDepositDB: Neuer bestätigter Hit gespeichert — "
                f"{address[:20]}… → {entity_name} (Case: {case_id})"
            )

    def bulk_import_from_list(
        self,
        entries: list[dict],
        source_key: str = "GITHUB_LABELS",
    ) -> int:
        """
        Bulk-Import aus einer Community-Liste.
        entries: list von {"address": ..., "entity": ..., "type": ...}
        Gibt Anzahl gespeicherter Einträge zurück.
        """
        count = 0
        for entry in entries:
            addr = entry.get("address", "").strip()
            if not addr:
                continue
            entity = entry.get("entity") or entry.get("label") or "Unknown"
            etype  = entry.get("type", "EXCHANGE").upper()
            conf   = entry.get("confidence_level", 2)
            ok = self.store_address(
                address=addr,
                entity_name=entity,
                entity_type=etype,
                source_key=source_key,
                confidence_level=conf,
                raw_data=entry,
            )
            if ok:
                count += 1
        logger.info(f"ExchangeDepositDB: Bulk import {count}/{len(entries)} Einträge via {source_key}")
        return count


# ---------------------------------------------------------------------------
# CioEngine — öffentliche Hauptklasse
# ---------------------------------------------------------------------------

class CioEngine:
    """
    Hauptklasse — koordiniert ClusterStore, CioAnalyser und ExchangeDepositDB.

    Wird vom Investigation-Pipeline aufgerufen:
      - Bei jeder TX-Analyse: process_tx()
      - Bei jedem Address-Lookup: attribute_address()
      - Nach bestätigtem Exchange-Hit: confirm_exchange_hit()
    """

    def __init__(self, db_conn, blockchain_adapter=None):
        self._conn    = db_conn
        self._adapter = blockchain_adapter
        self._store   = ClusterStore(db_conn)
        self._analyser = CioAnalyser(self._store)
        self._deposit_db = ExchangeDepositDB(db_conn)

    # ── TX-Analyse ──────────────────────────────────────────────────────────

    def process_tx(self, txid: str) -> Optional[CioTxResult]:
        """
        Analysiert eine TX aus dem Blockchain-Adapter.
        Holt Input-Adressen via Adapter (Bitcoin Core RPC oder Blockstream).
        """
        if self._adapter is None:
            logger.error("CioEngine: kein Blockchain-Adapter konfiguriert")
            return None

        tx = self._adapter.get_transaction(txid)
        if tx is None:
            logger.warning(f"CioEngine: TX nicht gefunden: {txid}")
            return None

        input_addresses = [inp.address for inp in tx.inputs if inp.address]
        output_values   = [int(out.value_sat) for out in tx.outputs if out.value_sat]

        return self._analyser.process_tx(txid, input_addresses, output_values)

    def process_tx_with_addresses(
        self,
        txid: str,
        input_addresses: list[str],
        output_values: Optional[list[int]] = None,
    ) -> CioTxResult:
        """
        Analysiert eine TX mit bereits bekannten Input-Adressen.
        Wird vom Investigation-Pipeline direkt aufgerufen
        (die Adressen sind dort bereits bekannt).
        """
        return self._analyser.process_tx(txid, input_addresses, output_values)

    # ── Adress-Attribution ──────────────────────────────────────────────────

    def attribute_address(self, address: str) -> AddressAttribution:
        """
        Vollständige Attribution einer Adresse.
        Prüft in Reihenfolge:
          1. Direkte Attribution (address_attributions, alle Sources)
          2. CIO-Cluster-Ableitung
          3. Blockchair Live-Lookup (falls kein Ergebnis)
        """
        result = AddressAttribution(address=address, found=False)

        # 1. Direkte Attribution aus DB
        with self._conn.cursor() as cur:
            cur.execute("""
                SELECT aa.entity_name, aa.entity_type, s.source_key,
                       s.display_name, aa.confidence_level
                FROM address_attributions aa
                JOIN attribution_sources s ON aa.source_id = s.source_id
                WHERE aa.address = %s
                ORDER BY s.priority ASC, aa.confidence_level ASC
                LIMIT 1
            """, (address,))
            row = cur.fetchone()
            if row:
                result.found = True
                result.direct_entity    = row[0]
                result.direct_source    = row[2]
                result.direct_confidence = row[4]

        # 2. CIO-Cluster-Ableitung
        cluster = self._store.get_cluster_for_address(address)
        if cluster:
            result.cluster_id   = cluster.cluster_id
            result.cluster_size = cluster.address_count
            if cluster.is_attributed:
                result.found = True
                result.cluster_entity       = cluster.entity_name
                result.cluster_entity_type  = cluster.entity_type
                result.cluster_confidence   = min((cluster.confidence_level or 2) + 1, 4)
                result.cluster_source       = cluster.attribution_source

        # 3. Bestes Ergebnis zusammenstellen
        if result.direct_entity:
            result.best_entity       = result.direct_entity
            result.best_entity_type  = result.direct_source  # source als Typ-Kontext
            result.best_confidence   = result.direct_confidence
            result.best_source       = result.direct_source
            result.attribution_method = "DIRECT"
            # Entity type aus DB nachholen
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT entity_type FROM address_attributions WHERE address = %s "
                    "ORDER BY confidence_level ASC LIMIT 1", (address,)
                )
                row = cur.fetchone()
                if row:
                    result.best_entity_type = row[0]
        elif result.cluster_entity:
            result.best_entity       = result.cluster_entity
            result.best_entity_type  = result.cluster_entity_type
            result.best_confidence   = result.cluster_confidence
            result.best_source       = result.cluster_source
            result.attribution_method = "CIO_CLUSTER"

        return result

    def attribute_address_with_live_lookup(self, address: str) -> AddressAttribution:
        """
        Wie attribute_address(), aber mit Blockchair-Fallback bei unbekannter Adresse.
        Langsamer (HTTP-Request), aber höhere Trefferquote.
        Nur im Investigation-Kontext aufrufen, nicht in Batch-Loops.
        """
        result = self.attribute_address(address)
        if result.found:
            return result

        # Blockchair Live-Lookup
        logger.info(f"CIO: Kein lokaler Treffer für {address[:20]}… — Blockchair-Lookup")
        bc_data = self._deposit_db.lookup_blockchair(address)
        if bc_data:
            # Blockchair liefert keinen direkten Entity-Namen für normale Adressen,
            # aber TX-Volumen und Muster können Hinweise geben
            tx_count = bc_data.get("transaction_count", 0)
            received = bc_data.get("received_sat", 0)

            # Hochvolumen-Adressen (>10.000 TX) sind typischerweise Exchange-Deposits
            if tx_count > 10_000:
                # Hohe Wahrscheinlichkeit Exchange, aber keine Namens-Attribution möglich
                result.found = True
                result.best_entity      = "Unbekannte Exchange (Hochvolumen)"
                result.best_entity_type = "EXCHANGE"
                result.best_confidence  = 3   # L3 — Indikativ
                result.best_source      = "BLOCKCHAIR_HEURISTIC"
                result.attribution_method = "VOLUME_HEURISTIC"
                logger.info(
                    f"CIO: {address[:20]}… → Hochvolumen-Adresse "
                    f"({tx_count:,} TXs) — wahrscheinlich Exchange-Deposit"
                )

        return result

    # ── Exchange-Hit bestätigen (Flywheel) ──────────────────────────────────

    def confirm_exchange_hit(
        self,
        address: str,
        entity_name: str,
        entity_type: str = "EXCHANGE",
        case_id: str = "",
        txid: Optional[str] = None,
    ) -> None:
        """
        Bestätigt einen Exchange-Hit nach abgeschlossener Untersuchung.
        1. Speichert in ExchangeDepositDB (address_attributions, Source: INVESTIGATION)
        2. Propagiert auf den gesamten CIO-Cluster der Adresse
        Dieser Flywheel-Effekt macht die DB mit jedem Fall besser.
        """
        # In Deposit-DB speichern
        self._deposit_db.confirm_investigation_hit(
            address=address,
            entity_name=entity_name,
            entity_type=entity_type,
            case_id=case_id,
            txid=txid,
        )

        # Cluster labeln und auf alle Cluster-Adressen ausweiten
        cluster = self._store.get_cluster_for_address(address)
        if cluster:
            self._store.label_cluster(
                cluster_id=cluster.cluster_id,
                entity_name=entity_name,
                entity_type=entity_type,
                source=f"INVESTIGATION:{case_id}",
                confidence_level=1,
            )
            # Alle Adressen im Cluster auch direkt in attribution_db speichern (L2)
            cluster_addrs = self._store.get_cluster_addresses(cluster.cluster_id)
            for addr in cluster_addrs:
                if addr == address:
                    continue  # Schon als L1 gespeichert
                self._deposit_db.store_address(
                    address=addr,
                    entity_name=entity_name,
                    entity_type=entity_type,
                    source_key="CIO_HEURISTIC",
                    confidence_level=2,  # L2 — CIO-Ableitung
                    raw_data={
                        "cluster_id": cluster.cluster_id,
                        "seed_case": case_id,
                        "method": "CIO_PROPAGATION",
                    },
                )
            logger.info(
                f"CIO: Flywheel — {len(cluster_addrs)} Adressen in Cluster "
                f"{cluster.cluster_id} als {entity_name} markiert"
            )
        else:
            logger.info(
                f"CIO: Kein Cluster für {address[:20]}… — "
                f"nur direkte Attribution gespeichert"
            )

    # ── Statistiken ─────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Gibt Statistiken über den aktuellen Zustand der CIO-DB zurück."""
        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cio_clusters")
            total_clusters = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM cio_address_cluster")
            total_addresses = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM cio_clusters WHERE entity_name IS NOT NULL"
            )
            attributed_clusters = cur.fetchone()[0]

            cur.execute("""
                SELECT entity_name, entity_type, COUNT(*) as cluster_count,
                       SUM(address_count) as address_count
                FROM cio_clusters
                WHERE entity_name IS NOT NULL
                GROUP BY entity_name, entity_type
                ORDER BY address_count DESC
                LIMIT 20
            """)
            top_entities = [
                {"entity": r[0], "type": r[1], "clusters": r[2], "addresses": r[3]}
                for r in cur.fetchall()
            ]

            cur.execute("SELECT COUNT(*) FROM address_attributions")
            direct_attributions = cur.fetchone()[0]

        return {
            "cio_clusters_total": total_clusters,
            "cio_clusters_attributed": attributed_clusters,
            "cio_addresses_tracked": total_addresses,
            "direct_attributions": direct_attributions,
            "top_attributed_entities": top_entities,
        }

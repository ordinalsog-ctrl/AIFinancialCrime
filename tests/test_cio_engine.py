"""
Tests für den CIO Cluster Engine.
Verwendet ein vollständiges In-Memory Mock-Backend — kein PostgreSQL nötig.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

from src.investigation.cio_engine import (
    CioCluster, CioTxResult, AddressAttribution,
    ClusterStore, CioAnalyser, ExchangeDepositDB, CioEngine,
    _is_likely_coinjoin,
)


# ---------------------------------------------------------------------------
# Fixtures: In-Memory DB Mock
# ---------------------------------------------------------------------------

class InMemoryClusterDB:
    """Vollständiges In-Memory Backend für ClusterStore-Tests."""

    def __init__(self):
        self._clusters: dict[int, dict] = {}   # cluster_id → dict
        self._addr_map: dict[str, int]  = {}   # address → cluster_id
        self._evidence: list[dict]      = []
        self._next_id = 1

    def cursor(self):
        return InMemoryCursor(self)

    def commit(self):
        pass  # alles already committed in-memory


class InMemoryCursor:
    def __init__(self, db: InMemoryClusterDB):
        self._db = db
        self._result = None

    def __enter__(self): return self
    def __exit__(self, *a): pass

    def execute(self, sql: str, params=None):
        db = self._db
        sql_clean = " ".join(sql.split()).lower()
        p = params or ()

        # get_cluster_id
        if "select cluster_id from cio_address_cluster where address" in sql_clean:
            addr = p[0]
            cid = db._addr_map.get(addr)
            self._result = [(cid,)] if cid is not None else []

        # get_cluster
        elif "select cluster_id, address_count, entity_name" in sql_clean and "where cluster_id" in sql_clean:
            cid = p[0]
            c = db._clusters.get(cid)
            if c:
                self._result = [(
                    c["cluster_id"], c["address_count"],
                    c.get("entity_name"), c.get("entity_type"),
                    c.get("attribution_source"), c.get("confidence_level"),
                    c.get("attributed_at"),
                )]
            else:
                self._result = []

        # get_cluster_addresses
        elif "select address from cio_address_cluster where cluster_id" in sql_clean:
            cid = p[0]
            addrs = [a for a, c in db._addr_map.items() if c == cid]
            self._result = [(a,) for a in addrs]

        # create cluster - INSERT INTO cio_clusters
        elif "insert into cio_clusters" in sql_clean and "returning cluster_id" in sql_clean:
            new_id = db._next_id
            db._next_id += 1
            db._clusters[new_id] = {
                "cluster_id": new_id, "address_count": 1,
                "entity_name": None, "entity_type": None,
                "attribution_source": None, "confidence_level": None,
                "attributed_at": None,
            }
            self._result = [(new_id,)]

        # insert address into cio_address_cluster
        elif "insert into cio_address_cluster" in sql_clean:
            addr, cid = p[0], p[1]
            if addr not in db._addr_map:  # ON CONFLICT DO NOTHING
                db._addr_map[addr] = cid

        # find largest cluster for merge
        elif "select cluster_id, address_count from cio_clusters" in sql_clean and "order by address_count desc" in sql_clean:
            cids = list(p[0])
            rows = [(cid, db._clusters[cid]["address_count"])
                    for cid in cids if cid in db._clusters]
            rows.sort(key=lambda x: x[1], reverse=True)
            self._result = rows[:1]

        # update address cluster_id (merge redirect)
        elif "update cio_address_cluster set cluster_id" in sql_clean:
            winner, losers = p[0], list(p[1])
            for addr, cid in db._addr_map.items():
                if cid in losers:
                    db._addr_map[addr] = winner

        # update cluster address_count after merge
        elif "update cio_clusters set" in sql_clean and "address_count" in sql_clean and "select count" in sql_clean:
            cid = p[0]
            count = sum(1 for c in db._addr_map.values() if c == cid)
            if cid in db._clusters:
                db._clusters[cid]["address_count"] = count

        # delete loser clusters
        elif "delete from cio_clusters where cluster_id" in sql_clean:
            losers = list(p[0])
            for cid in losers:
                db._clusters.pop(cid, None)

        # insert evidence
        elif "insert into cio_evidence" in sql_clean:
            db._evidence.append({"txid": p[0], "cluster_id": p[1], "addresses": p[2]})

        # label cluster
        elif "update cio_clusters set" in sql_clean and "entity_name" in sql_clean:
            cid = p[4]  # last param
            if cid in db._clusters:
                db._clusters[cid].update({
                    "entity_name": p[0], "entity_type": p[1],
                    "attribution_source": p[2], "confidence_level": p[3],
                    "attributed_at": datetime.now(timezone.utc),
                })

        # propagate: check direct attribution of address
        elif "select aa.entity_name, aa.entity_type, s.source_key" in sql_clean:
            self._result = []  # no direct attributions in pure CIO tests

        # propagate: check existing cluster confidence
        elif "select confidence_level from cio_clusters where cluster_id" in sql_clean:
            cid = p[0]
            c = db._clusters.get(cid, {})
            conf = c.get("confidence_level")
            self._result = [(conf,)] if conf is not None else []

        else:
            self._result = []

    def fetchone(self):
        if self._result:
            return self._result[0]
        return None

    def fetchall(self):
        return self._result or []

    @property
    def rowcount(self):
        return len(self._result) if self._result else 0


def make_store():
    db = InMemoryClusterDB()
    return ClusterStore(db), db

def make_analyser():
    store, db = make_store()
    return CioAnalyser(store), store, db


# ---------------------------------------------------------------------------
# T1: CoinJoin-Erkennung
# ---------------------------------------------------------------------------

class TestCoinJoinDetection:

    def test_too_few_inputs_not_coinjoin(self):
        addrs = ["addr1", "addr2", "addr3"]
        assert _is_likely_coinjoin(addrs, []) is False

    def test_many_unique_inputs_no_equal_outputs(self):
        addrs = [f"addr{i}" for i in range(8)]
        values = [10000, 20000, 30000, 40000, 50000]
        assert _is_likely_coinjoin(addrs, values) is False

    def test_coinjoin_detected(self):
        addrs = [f"addr{i}" for i in range(8)]
        # 80%+ gleiche Outputs
        values = [100000] * 9 + [12345]
        assert _is_likely_coinjoin(addrs, values) is True

    def test_same_address_repeated_not_coinjoin(self):
        addrs = ["addr1"] * 8  # Gleiche Adresse mehrfach
        values = [100000] * 8
        assert _is_likely_coinjoin(addrs, values) is False

    def test_exact_threshold(self):
        addrs = [f"addr{i}" for i in range(5)]
        values = [100000] * 4 + [99999]  # genau 80%
        assert _is_likely_coinjoin(addrs, values) is True


# ---------------------------------------------------------------------------
# T2: ClusterStore — grundlegende Operationen
# ---------------------------------------------------------------------------

class TestClusterStore:

    def test_create_and_get_cluster(self):
        store, db = make_store()
        cid = store.create_cluster("1ABC", seed_txid="tx1")
        assert cid is not None
        cluster = store.get_cluster(cid)
        assert cluster is not None
        assert cluster.address_count == 1
        assert cluster.entity_name is None

    def test_ensure_cluster_idempotent(self):
        store, db = make_store()
        cid1 = store.ensure_cluster("1ABC")
        cid2 = store.ensure_cluster("1ABC")
        assert cid1 == cid2

    def test_get_cluster_for_unknown_address(self):
        store, db = make_store()
        result = store.get_cluster_for_address("unknownAddr")
        assert result is None

    def test_merge_two_clusters(self):
        store, db = make_store()
        cid1 = store.ensure_cluster("addr1")
        cid2 = store.ensure_cluster("addr2")
        assert cid1 != cid2

        winner = store.merge([cid1, cid2], txid="tx_merge", all_addresses=["addr1", "addr2"])
        # Beide Adressen im selben Cluster
        assert store.get_cluster_id("addr1") == winner
        assert store.get_cluster_id("addr2") == winner
        # Adresszahl korrekt
        cluster = store.get_cluster(winner)
        assert cluster.address_count == 2

    def test_merge_three_clusters(self):
        store, db = make_store()
        cids = [store.ensure_cluster(f"addr{i}") for i in range(3)]
        winner = store.merge(cids, "tx3", [f"addr{i}" for i in range(3)])
        for i in range(3):
            assert store.get_cluster_id(f"addr{i}") == winner

    def test_label_cluster(self):
        store, db = make_store()
        cid = store.ensure_cluster("addr1")
        store.label_cluster(cid, "Binance", "EXCHANGE", "INVESTIGATION", 1)
        cluster = store.get_cluster(cid)
        assert cluster.entity_name == "Binance"
        assert cluster.entity_type == "EXCHANGE"
        assert cluster.confidence_level == 1

    def test_get_cluster_addresses(self):
        store, db = make_store()
        cid = store.ensure_cluster("addr1")
        store.ensure_cluster("addr2")
        cid2 = store.get_cluster_id("addr2")
        # Merge both into same cluster
        store.merge([cid, cid2], "tx", ["addr1", "addr2"])
        final_cid = store.get_cluster_id("addr1")
        addrs = store.get_cluster_addresses(final_cid)
        assert set(addrs) == {"addr1", "addr2"}


# ---------------------------------------------------------------------------
# T3: CioAnalyser — TX-Analyse
# ---------------------------------------------------------------------------

class TestCioAnalyser:

    def test_single_input_no_cio(self):
        analyser, store, db = make_analyser()
        result = analyser.process_tx("tx1", ["addr1"], [50000])
        assert result.cluster_id is None
        assert result.was_merged is False
        assert result.is_likely_coinjoin is False

    def test_two_inputs_merged(self):
        analyser, store, db = make_analyser()
        result = analyser.process_tx("tx1", ["addr1", "addr2"], [50000])
        assert result.cluster_id is not None
        assert result.was_merged is True
        assert store.get_cluster_id("addr1") == store.get_cluster_id("addr2")

    def test_coinjoin_not_merged(self):
        analyser, store, db = make_analyser()
        addrs = [f"addr{i}" for i in range(8)]
        values = [100000] * 9 + [12345]
        result = analyser.process_tx("tx_cj", addrs, values)
        assert result.is_likely_coinjoin is True
        assert result.was_merged is False
        # Jede Adresse hat eigenen Cluster
        cluster_ids = {store.get_cluster_id(a) for a in addrs}
        assert len(cluster_ids) == len(addrs)  # alle getrennt

    def test_incremental_cluster_growth(self):
        analyser, store, db = make_analyser()
        # TX 1: addr1 + addr2 → Cluster A
        analyser.process_tx("tx1", ["addr1", "addr2"])
        cid_a = store.get_cluster_id("addr1")
        # TX 2: addr2 + addr3 → merged mit Cluster A
        analyser.process_tx("tx2", ["addr2", "addr3"])
        cid_after = store.get_cluster_id("addr3")
        assert cid_after == cid_a
        assert store.get_cluster_id("addr1") == cid_a
        assert store.get_cluster_id("addr2") == cid_a

    def test_duplicate_addresses_deduplicated(self):
        analyser, store, db = make_analyser()
        result = analyser.process_tx("tx1", ["addr1", "addr1", "addr2"])
        assert result.was_merged is True
        cluster_ids = {store.get_cluster_id("addr1"), store.get_cluster_id("addr2")}
        assert len(cluster_ids) == 1

    def test_empty_addresses_ignored(self):
        analyser, store, db = make_analyser()
        result = analyser.process_tx("tx1", ["", None, "addr1", "addr2"])
        assert result.was_merged is True

    def test_attribution_returned_when_cluster_known(self):
        analyser, store, db = make_analyser()
        # Cluster erstellen und labeln
        cid = store.ensure_cluster("known_addr")
        store.label_cluster(cid, "Kraken", "EXCHANGE", "MANUAL", 1)
        # TX die known_addr mit unbekannter verknüpft
        result = analyser.process_tx("tx1", ["known_addr", "new_addr"])
        assert result.attribution is not None
        assert result.attribution.entity_name == "Kraken"


# ---------------------------------------------------------------------------
# T4: ExchangeDepositDB
# ---------------------------------------------------------------------------

class TestExchangeDepositDB:

    def _make_db_conn(self):
        """Mock-Conn für ExchangeDepositDB (nur store_address nutzen wir hier)."""
        conn = MagicMock()
        cur  = MagicMock()
        conn.cursor.return_value.__enter__ = lambda s: cur
        conn.cursor.return_value.__exit__  = MagicMock(return_value=False)
        cur.fetchone.return_value = (1, 5)  # source_id=1, priority=5
        cur.rowcount = 1
        return conn, cur

    def test_label_matching_binance(self):
        db = ExchangeDepositDB(MagicMock())
        result = db._match_label_to_entity("Binance Hot Wallet")
        assert result == ("Binance", "EXCHANGE")

    def test_label_matching_mixer(self):
        db = ExchangeDepositDB(MagicMock())
        result = db._match_label_to_entity("Wasabi Wallet Coinjoin")
        assert result == ("Wasabi Wallet", "MIXER")

    def test_label_matching_unknown(self):
        db = ExchangeDepositDB(MagicMock())
        result = db._match_label_to_entity("random unknown label xyz")
        assert result is None

    def test_bulk_import(self):
        conn, cur = self._make_db_conn()
        db = ExchangeDepositDB(conn)
        entries = [
            {"address": "1AAA", "entity": "Binance", "type": "EXCHANGE"},
            {"address": "1BBB", "entity": "Kraken",  "type": "EXCHANGE"},
            {"address": "",     "entity": "Bad",     "type": "EXCHANGE"},  # leer → skip
        ]
        count = db.bulk_import_from_list(entries)
        assert count == 2  # leer übersprungen

    def test_confirm_investigation_hit(self):
        conn, cur = self._make_db_conn()
        db = ExchangeDepositDB(conn)
        db.confirm_investigation_hit(
            address="1ABC", entity_name="Binance", entity_type="EXCHANGE",
            case_id="CASE-001", txid="tx123"
        )
        # store_address sollte aufgerufen worden sein
        assert conn.commit.called


# ---------------------------------------------------------------------------
# T5: CioEngine — Integration
# ---------------------------------------------------------------------------

class TestCioEngine:

    def _make_engine(self):
        """Engine mit In-Memory Cluster-Store und Mock-Attribution-DB."""
        db = InMemoryClusterDB()

        # Attribution DB mock (für direkte Lookups)
        attr_cur = MagicMock()
        attr_cur.__enter__ = lambda s: attr_cur
        attr_cur.__exit__ = MagicMock(return_value=False)
        attr_cur.fetchone.return_value = None
        attr_cur.fetchall.return_value = []
        attr_cur.rowcount = 0
        db.cursor = lambda: attr_cur  # Override für attribute_address

        # Aber ClusterStore braucht den echten InMemory Cursor
        cluster_db = InMemoryClusterDB()
        engine = CioEngine.__new__(CioEngine)
        engine._conn    = cluster_db
        engine._adapter = None
        engine._store   = ClusterStore(cluster_db)
        engine._analyser = CioAnalyser(engine._store)
        engine._deposit_db = MagicMock(spec=ExchangeDepositDB)
        engine._deposit_db.store_address.return_value = True
        return engine, cluster_db

    def test_process_tx_with_addresses(self):
        engine, db = self._make_engine()
        result = engine.process_tx_with_addresses("tx1", ["addr1", "addr2"], [50000])
        assert result.was_merged is True
        assert result.cluster_id is not None

    def test_flywheel_confirm_exchange_hit(self):
        engine, db = self._make_engine()
        # Cluster erstellen
        engine.process_tx_with_addresses("tx1", ["addr1", "addr2"])
        # Exchange bestätigen
        engine.confirm_exchange_hit("addr1", "Binance", case_id="CASE-001")
        # Cluster sollte jetzt als Binance markiert sein
        cluster = engine._store.get_cluster_for_address("addr1")
        assert cluster is not None
        assert cluster.entity_name == "Binance"
        # Deposit-DB sollte aufgerufen worden sein für beide Adressen
        assert engine._deposit_db.store_address.called

    def test_flywheel_propagates_to_all_cluster_members(self):
        engine, db = self._make_engine()
        engine.process_tx_with_addresses("tx1", ["addr1", "addr2", "addr3"])
        engine.confirm_exchange_hit("addr1", "Kraken", case_id="CASE-002")
        # Alle drei Adressen im selben Cluster, alle als Kraken markiert
        for addr in ["addr1", "addr2", "addr3"]:
            c = engine._store.get_cluster_for_address(addr)
            assert c.entity_name == "Kraken", f"{addr} nicht als Kraken markiert"

    def test_no_adapter_returns_none(self):
        engine, db = self._make_engine()
        result = engine.process_tx("unknown_txid")
        assert result is None

    def test_coinjoin_not_merged_in_engine(self):
        engine, db = self._make_engine()
        addrs = [f"addr{i}" for i in range(8)]
        values = [100000] * 9 + [12345]
        result = engine.process_tx_with_addresses("tx_cj", addrs, values)
        assert result.is_likely_coinjoin is True
        # Alle Adressen in getrennten Clustern
        cluster_ids = {engine._store.get_cluster_id(a) for a in addrs}
        assert len(cluster_ids) == len(addrs)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    results = []
    ok  = lambda m: results.append(f"✅ {m}")
    bad = lambda m: results.append(f"❌ {m}")

    test_classes = [
        TestCoinJoinDetection,
        TestClusterStore,
        TestCioAnalyser,
        TestExchangeDepositDB,
        TestCioEngine,
    ]

    for cls in test_classes:
        instance = cls()
        for method_name in [m for m in dir(cls) if m.startswith("test_")]:
            try:
                getattr(instance, method_name)()
                ok(f"{cls.__name__}.{method_name}")
            except Exception as e:
                bad(f"{cls.__name__}.{method_name}: {e}")

    passed = sum(1 for r in results if r.startswith("✅"))
    failed = sum(1 for r in results if r.startswith("❌"))
    for r in results:
        print(r)
    print(f"\n{passed} passed  |  {failed} failed")
    if failed:
        sys.exit(1)

from __future__ import annotations

import json
import os
import asyncio
import unittest
from unittest.mock import patch

from src.api import report_endpoint
from src.api import report_helpers


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


class _FakeSpendScanRpc:
    def __init__(self):
        self.calls: list[tuple[str, tuple | None]] = []

    def call(self, method: str, params=None):
        params = params or []
        self.calls.append((method, tuple(params)))
        if method == "gettxout":
            return None
        if method == "getrawtransaction":
            return {"blockheight": 100}
        if method == "getblockcount":
            return 101
        if method == "getblockhash":
            return "blockhash101"
        if method == "getblock":
            return {
                "tx": [
                    {
                        "txid": "5e1e80ff0bb4362ccdd2626df3b6c5f95c8a661c4e8ab27be1d489c707b66371",
                        "vin": [
                            {
                                "txid": "1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101",
                                "vout": 0,
                            }
                        ],
                    }
                ]
            }
        raise AssertionError(f"unexpected rpc method {method}")


class ExchangeIntelIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        report_endpoint._attribution_cache.clear()

    def test_exchange_intel_lookup_accepts_entity_object(self) -> None:
        payload = {
            "address": "bc1qexample",
            "network": "bitcoin",
            "found": True,
            "entity": {"name": "Coinbase", "type": "exchange"},
            "labels": [],
            "best_source_type": "official_por",
        }
        with patch.dict(os.environ, {"EXCHANGE_INTEL_API_URL": "http://localhost:8080"}, clear=False):
            with patch("urllib.request.urlopen", return_value=_FakeResponse(payload)):
                result = report_endpoint._exchange_intel_lookup("bc1qexample")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["exchange"], "Coinbase")
        self.assertEqual(result["source"], "exchange-intel/official_por")
        self.assertEqual(result["confidence"], "L1")

    def test_exchange_intel_lookup_accepts_legacy_entity_string(self) -> None:
        payload = {
            "address": "bc1qlegacy",
            "network": "bitcoin",
            "found": True,
            "entity": "Kraken",
            "labels": [],
            "best_source_type": "wallet_label",
        }
        with patch.dict(os.environ, {"EXCHANGE_INTEL_API_URL": "http://localhost:8080"}, clear=False):
            with patch("urllib.request.urlopen", return_value=_FakeResponse(payload)):
                result = report_endpoint._exchange_intel_lookup("bc1qlegacy")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["exchange"], "Kraken")
        self.assertEqual(result["confidence"], "L2")

    def test_acam_burden_excludes_downstream_only_hits(self) -> None:
        self.assertTrue(
            report_endpoint._is_acam_burdenable_attribution(
                {
                    "exchange": "Coinbase",
                    "source": "exchange-intel/seed",
                    "confidence": "L1",
                }
            )
        )
        self.assertFalse(
            report_endpoint._is_acam_burdenable_attribution(
                {
                    "exchange": "Coinbase",
                    "source": "downstream-analysis",
                    "confidence": "L3",
                }
            )
        )

    def test_check_address_uses_agent_only_for_exchange_detection(self) -> None:
        exchange_hit = {
            "exchange": "Kraken",
            "label": "Kraken (wallet_label)",
            "wallet_id": "",
            "source": "exchange-intel/wallet_label",
            "confidence": "L2",
            "is_sanctioned": False,
        }

        with patch.object(report_endpoint, "_exchange_intel_lookup", return_value=exchange_hit) as intel_mock, \
             patch.object(report_endpoint, "_chainalysis_check", return_value=False):
            result = report_endpoint._check_address("35Pt1UNGaikeAEFzPsdzAghyrNoyjbdNVo")

        intel_mock.assert_called_once_with("35Pt1UNGaikeAEFzPsdzAghyrNoyjbdNVo")
        self.assertEqual(result["exchange"], "Kraken")
        self.assertEqual(result["source"], "exchange-intel/wallet_label")

    def test_get_spending_info_falls_back_to_local_block_scan(self) -> None:
        rpc = _FakeSpendScanRpc()
        with patch("urllib.request.urlopen", side_effect=RuntimeError("dns unavailable")):
            state, spending_txid = report_endpoint._get_spending_info(
                "1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101",
                0,
                rpc,
            )

        self.assertEqual(state, "spent")
        self.assertEqual(
            spending_txid,
            "5e1e80ff0bb4362ccdd2626df3b6c5f95c8a661c4e8ab27be1d489c707b66371",
        )

    def test_generate_report_marks_recipient_exchange_and_continues_tracing(self) -> None:
        req = report_endpoint.ReportRequest(
            case_id="AIFC-TEST-RECIPIENT-EXCHANGE",
            victim_name="Test User",
            incident_date="2026-03-24",
            fraud_txid="338f09e20b29ba6b9529b69dffd348a5736579310a4b560a94bd571579160681",
            fraud_amount_btc="0.25015009",
            victim_addresses=["bc1qvictimaddress0000000000000000000000000"],
            recipient_address="33qXiU6YcrZv2YBi2mCoYKgEohiN2REkJ2",
        )

        fraud_tx = {
            "vout": [
                {
                    "value": 0.25015009,
                    "scriptPubKey": {"address": "33qXiU6YcrZv2YBi2mCoYKgEohiN2REkJ2"},
                }
            ],
            "vin": [
                {
                    "prevout": {
                        "scriptpubkey_address": "bc1qvictimaddress0000000000000000000000000",
                        "value": 0.25015009,
                    }
                }
            ],
        }

        exchange_hit = {
            "exchange": "Coinbase",
            "label": "Coinbase (seed)",
            "wallet_id": "",
            "source": "exchange-intel/seed",
            "confidence": "L1",
            "is_sanctioned": False,
        }

        class _MinimalConn:
            def close(self) -> None:
                return None

        with patch.object(report_endpoint, "_get_conn", return_value=_MinimalConn()), \
             patch.object(report_endpoint, "_get_rpc", return_value=object()), \
             patch.object(report_endpoint, "_get_tx", return_value=fraud_tx), \
             patch.object(report_endpoint, "_save_tx_to_db", return_value=None), \
             patch.object(report_endpoint, "_get_tx_block_info", return_value=(123456, "2026-03-24 12:00:00 UTC")), \
             patch.object(report_endpoint, "_get_tx_outputs", return_value=[("33qXiU6YcrZv2YBi2mCoYKgEohiN2REkJ2", 0.25015009)]), \
             patch.object(report_endpoint, "_generate_pdf", return_value="/tmp/test.pdf"), \
             patch.object(report_endpoint, "_generate_freeze_requests", return_value=["/tmp/freeze.pdf"]), \
             patch.object(
                 report_endpoint,
                 "_trace_victim_chain",
                 return_value=[
                     {
                         "hop": 1,
                         "label": "UTXO Weiterleitung",
                         "txid": "41606d97ba4591be664816cac2f325808c0c47009a3bdf14e20051fecda5a8a2",
                         "block": 123457,
                         "timestamp": "2026-03-24 12:01:00 UTC",
                         "from_addresses": [("33qXiU6YcrZv2YBi2mCoYKgEohiN2REkJ2", 0.25015009)],
                         "to_addresses": [("bc1qnextnode000000000000000000000000000", 0.25)],
                         "fee_btc": None,
                         "confidence": "L1",
                         "confidence_label": "Mathematisch bewiesen",
                         "method": "Direkter UTXO-Link",
                         "notes": "Weiterleitung nach Exchange-Einzahlung.",
                         "is_sanctioned": False,
                         "chain_end_reason": None,
                     }
                 ],
             ) as trace_mock:

            def _check_side_effect(address: str, use_downstream: bool = True):
                if address == "33qXiU6YcrZv2YBi2mCoYKgEohiN2REkJ2" and not use_downstream:
                    report_endpoint._attribution_cache[address] = {
                        **exchange_hit,
                        "_downstream_checked": False,
                    }
                    return exchange_hit
                return {
                    "exchange": None,
                    "is_sanctioned": False,
                    "source": None,
                    "label": None,
                    "wallet_id": None,
                    "confidence": "L1",
                    "_downstream_checked": use_downstream,
                }

            with patch.object(report_endpoint, "_check_address", side_effect=_check_side_effect):
                response = asyncio.run(report_endpoint.generate_report(req))

        trace_mock.assert_called_once()
        payload = json.loads(response.body)
        self.assertEqual(payload["case_id"], "AIFC-TEST-RECIPIENT-EXCHANGE")
        self.assertEqual(payload["hops_found"], 2)
        self.assertEqual(payload["exchanges_identified"], ["Coinbase"])
        self.assertEqual(payload["freeze_requests_generated"], 1)

    def test_flow_graph_uses_input_contribution_for_multi_input_single_target(self) -> None:
        graph = report_helpers._build_flow_graph(
            ["bc1qvictim1", "bc1qvictim2"],
            "bc1qrecipient",
            [
                {
                    "hop": 0,
                    "txid": "tx-hop-0",
                    "from_addresses": [("bc1qvictim1", 0.4), ("bc1qvictim2", 0.6)],
                    "to_addresses": [("bc1qrecipient", 1.0)],
                    "confidence": "L1",
                    "confidence_label": "Mathematically proven",
                }
            ],
        )

        edge_by_source = {edge["from"]: edge for edge in graph["edges"]}
        self.assertEqual(edge_by_source["bc1qvictim1"]["amount_context"], "input_contribution")
        self.assertEqual(edge_by_source["bc1qvictim2"]["amount_context"], "input_contribution")
        self.assertEqual(edge_by_source["bc1qvictim1"]["amount_btc"], 0.4)
        self.assertEqual(edge_by_source["bc1qvictim2"]["amount_btc"], 0.6)

    def test_flow_graph_marks_multi_input_multi_output_edge_amount_as_aggregate(self) -> None:
        graph = report_helpers._build_flow_graph(
            ["bc1qvictim1", "bc1qvictim2"],
            "bc1qrecipient1",
            [
                {
                    "hop": 0,
                    "txid": "tx-hop-0",
                    "from_addresses": [("bc1qvictim1", 0.4), ("bc1qvictim2", 0.6)],
                    "to_addresses": [("bc1qrecipient1", 0.5), ("bc1qrecipient2", 0.5)],
                    "confidence": "L1",
                    "confidence_label": "Mathematically proven",
                }
            ],
        )

        self.assertTrue(graph["edges"])
        self.assertTrue(all(edge["amount_context"] == "aggregate_transaction" for edge in graph["edges"]))
        self.assertTrue(all(edge["amount_btc"] is None for edge in graph["edges"]))


if __name__ == "__main__":
    unittest.main()

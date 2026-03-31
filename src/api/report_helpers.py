from __future__ import annotations

from typing import Optional

KNOWN_EXCHANGES = {
    "huobi": "Huobi",
    "binance": "Binance",
    "coinbase": "Coinbase",
    "kraken": "Kraken",
    "bitfinex": "Bitfinex",
    "okx": "OKX",
    "poloniex": "Poloniex",
    "kucoin": "KuCoin",
    "bybit": "Bybit",
    "bitstamp": "Bitstamp",
    "gemini": "Gemini",
    "bittrex": "Bittrex",
    "bitmex": "BitMEX",
    "gate.io": "Gate.io",
    "htx": "Huobi",
    "gate": "Gate.io",
    "bitget": "Bitget",
    "mexc": "MEXC",
}

EXCHANGE_COMPLIANCE = {
    "Huobi": "compliance@huobi.com",
    "Binance": "law_enforcement@binance.com",
    "Coinbase": "compliance@coinbase.com",
    "Kraken": "compliance@kraken.com",
    "Poloniex": "support@poloniex.com",
    "OKX": "compliance@okx.com",
    "Bybit": "compliance@bybit.com",
    "Bitstamp": "legal@bitstamp.net",
    "Bitfinex": "compliance@bitfinex.com",
    "Gate.io": "compliance@gate.io",
}


def _canonical_exchange_name(raw_name: str) -> str:
    return next(
        (name for key, name in KNOWN_EXCHANGES.items() if key in raw_name.lower()),
        raw_name,
    )


def _extract_exchange_intel_entity_name(payload: dict) -> str:
    entity = payload.get("entity")
    if isinstance(entity, dict):
        name = entity.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    if isinstance(entity, str) and entity.strip():
        return entity.strip()
    for label in payload.get("labels") or []:
        if not isinstance(label, dict):
            continue
        raw_name = label.get("entity_name") or label.get("source_name")
        if isinstance(raw_name, str) and raw_name.strip():
            return raw_name.strip()
    return ""


def _confidence_from_source_type(source_type: str) -> tuple[int, str]:
    if source_type in ("official_por", "seed"):
        return 1, "L1"
    return 2, "L2"


def _is_acam_burdenable_attribution(attribution: Optional[dict]) -> bool:
    if not attribution or not attribution.get("exchange"):
        return False
    source = str(attribution.get("source") or "")
    if source.startswith("downstream-analysis"):
        return False
    return str(attribution.get("confidence") or "") in {"L1", "L2"}


def _short_address(address: str, left: int = 10, right: int = 6) -> str:
    if not address:
        return "—"
    if len(address) <= left + right + 1:
        return address
    return f"{address[:left]}…{address[-right:]}"


def _build_flow_graph(victim_addresses: list[str], recipient_address: str, all_hops: list[dict]) -> dict:
    kind_priority = {"address": 0, "recipient": 1, "victim": 2, "exchange": 3}
    node_map: dict[str, dict] = {}
    edges: list[dict] = []
    max_column = 0

    def _pick_kind(current: str, candidate: str) -> str:
        return candidate if kind_priority.get(candidate, 0) >= kind_priority.get(current, 0) else current

    def _upsert_node(
        address: str,
        column: int,
        *,
        kind: str = "address",
        exchange: str = "",
        sanctioned: bool = False,
    ) -> dict:
        nonlocal max_column
        if not address:
            raise ValueError("address required")
        max_column = max(max_column, column)
        node = node_map.get(address)
        if node is None:
            node = {
                "id": address,
                "address": address,
                "column": column,
                "kind": kind,
                "exchange": exchange or "",
                "is_sanctioned": bool(sanctioned),
                "total_in_btc": 0.0,
                "total_out_btc": 0.0,
                "has_change_output": False,
                "chain_end_reason": "",
            }
            node_map[address] = node
        else:
            node["column"] = min(node["column"], column)
            node["kind"] = _pick_kind(node.get("kind", "address"), kind)
            if exchange and not node.get("exchange"):
                node["exchange"] = exchange
            node["is_sanctioned"] = node.get("is_sanctioned", False) or bool(sanctioned)
        return node

    for victim in dict.fromkeys(victim_addresses):
        _upsert_node(victim, 0, kind="victim")
    if recipient_address:
        _upsert_node(recipient_address, 1, kind="recipient")

    for hop in all_hops:
        hop_index = int(hop.get("hop") or 0)
        known_source_columns = [
            node_map[addr]["column"]
            for addr, _ in (hop.get("from_addresses") or [])
            if addr and addr in node_map
        ]
        from_column = min(known_source_columns) if known_source_columns else (0 if hop_index == 0 else hop_index)
        to_column = from_column + 1
        from_entries = [tuple(item) for item in (hop.get("from_addresses") or [])]
        to_entries = [tuple(item) for item in (hop.get("to_addresses") or [])]
        exchange_addresses = set(hop.get("exchange_addresses") or [])
        exchange_name = str(hop.get("exchange") or "")
        from_addrs = {addr for addr, _ in from_entries if addr}

        for addr, amount in from_entries:
            if not addr:
                continue
            kind = "victim" if addr in victim_addresses else "recipient" if addr == recipient_address else "address"
            if addr in exchange_addresses:
                kind = "exchange"
            node = _upsert_node(
                addr,
                from_column,
                kind=kind,
                exchange=exchange_name if addr in exchange_addresses else "",
                sanctioned=bool(hop.get("is_sanctioned")),
            )
            try:
                node["total_out_btc"] += float(amount or 0)
            except Exception:
                pass

        for addr, amount in to_entries:
            if not addr:
                continue
            is_exchange_addr = addr in exchange_addresses
            is_recipient_addr = hop_index == 0 and addr == recipient_address
            is_change_addr = addr in from_addrs
            kind = "exchange" if is_exchange_addr else "recipient" if is_recipient_addr else "address"
            node = _upsert_node(
                addr,
                to_column,
                kind=kind,
                exchange=exchange_name if is_exchange_addr else "",
                sanctioned=bool(hop.get("is_sanctioned")),
            )
            try:
                node["total_in_btc"] += float(amount or 0)
            except Exception:
                pass
            if hop.get("chain_end_reason") and not node.get("chain_end_reason"):
                node["chain_end_reason"] = hop.get("chain_end_reason") or ""
            if is_change_addr:
                node["has_change_output"] = True
                continue
            for src_addr, _src_amount in from_entries:
                if not src_addr or src_addr == addr:
                    continue
                edge_id = f"{hop.get('txid', '')}:{src_addr}:{addr}:{len(edges)}"
                try:
                    edge_amount = float(amount or 0)
                except Exception:
                    edge_amount = 0.0
                edges.append(
                    {
                        "id": edge_id,
                        "txid": hop.get("txid", ""),
                        "from": src_addr,
                        "to": addr,
                        "amount_btc": edge_amount,
                        "hop": hop_index,
                        "confidence": hop.get("confidence", ""),
                        "confidence_label": hop.get("confidence_label", ""),
                        "label": hop.get("label", ""),
                        "method": hop.get("method", ""),
                        "notes": hop.get("notes", ""),
                        "block": hop.get("block", 0),
                        "timestamp": hop.get("timestamp", ""),
                        "chain_end_reason": hop.get("chain_end_reason"),
                        "is_exchange_edge": is_exchange_addr,
                        "is_sanctioned": bool(hop.get("is_sanctioned")),
                    }
                )

    for node in node_map.values():
        node["short_address"] = _short_address(node["address"])
        if node["kind"] == "victim":
            node["display_label"] = "Victim"
        elif node["kind"] == "recipient":
            node["display_label"] = "Recipient"
        elif node["kind"] == "exchange":
            node["display_label"] = node.get("exchange") or "Exchange"
        else:
            node["display_label"] = node["short_address"]

    nodes = sorted(node_map.values(), key=lambda item: (item["column"], item["kind"], item["address"]))
    exchange_count = sum(1 for node in nodes if node.get("kind") == "exchange")
    lanes = [{"column": 0, "label": "Victim"}] + [
        {"column": column, "label": f"Hop {column - 1}"}
        for column in range(1, max_column + 1)
    ]
    return {
        "lanes": lanes,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "exchange_count": exchange_count,
            "max_column": max_column,
        },
    }

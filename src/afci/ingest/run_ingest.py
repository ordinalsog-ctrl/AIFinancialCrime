from __future__ import annotations

import argparse
from functools import lru_cache
from pathlib import Path
from typing import Any

from afci.config import Settings
from afci.db.postgres import (
    BlockRow,
    TxInputRow,
    TxOutputRow,
    TxRow,
    apply_schema,
    connect,
    get_ingest_cursor,
    link_spent_outputs_for_tx,
    set_ingest_cursor,
    tx,
    upsert_address,
    upsert_block,
    upsert_tx,
    upsert_tx_input,
    upsert_tx_output,
)
from afci.ingest.bitcoin_rpc import BitcoinRpcClient
from afci.ingest.parser import parse_verbose_block


@lru_cache(maxsize=50000)
def _fetch_tx(rpc: BitcoinRpcClient, txid: str) -> dict[str, Any]:
    return rpc.call("getrawtransaction", [txid, True])


def _resolve_prevout(rpc: BitcoinRpcClient, prev_txid: str, prev_vout: int) -> dict[str, Any] | None:
    prev_tx = _fetch_tx(rpc, prev_txid)
    vouts = prev_tx.get("vout", [])
    if prev_vout < 0 or prev_vout >= len(vouts):
        return None
    vout = vouts[prev_vout]
    script_pub_key = vout.get("scriptPubKey", {})
    if "address" in script_pub_key:
        address = script_pub_key["address"]
    else:
        addresses = script_pub_key.get("addresses") or []
        address = addresses[0] if addresses else None
    return {
        "address": address,
        "value": vout.get("value"),
    }


def ingest_block(rpc: BitcoinRpcClient, conn, height: int, cursor_key: str) -> None:
    block_hash = rpc.call("getblockhash", [height])
    verbose_block = rpc.call("getblock", [block_hash, 2])
    block = parse_verbose_block(
        verbose_block,
        prevout_resolver=lambda txid, vout: _resolve_prevout(rpc, txid, vout),
    )

    with tx(conn):
        with conn.cursor() as cur:
            upsert_block(
                cur,
                BlockRow(
                    height=block.height,
                    block_hash=block.block_hash,
                    timestamp=block.timestamp,
                ),
            )

            for n_tx in block.transactions:
                upsert_tx(
                    cur,
                    TxRow(
                        txid=n_tx.txid,
                        block_height=block.height,
                        fee_sats=n_tx.fee_sats,
                        vsize=n_tx.vsize,
                    ),
                )

                for txin in n_tx.inputs:
                    if txin.address:
                        upsert_address(cur, txin.address, script_type=None)
                    upsert_tx_input(
                        cur,
                        TxInputRow(
                            txid=n_tx.txid,
                            vin_index=txin.vin_index,
                            prev_txid=txin.prev_txid,
                            prev_vout=txin.prev_vout,
                            address=txin.address,
                            amount_sats=txin.amount_sats,
                        ),
                    )

                for txout in n_tx.outputs:
                    if txout.address:
                        upsert_address(cur, txout.address, script_type=txout.script_type)
                        upsert_tx_output(
                        cur,
                        TxOutputRow(
                            txid=n_tx.txid,
                            vout_index=txout.vout_index,
                            address=txout.address,
                            script_type=txout.script_type,
                            amount_sats=txout.amount_sats,
                        ),
                    )
                link_spent_outputs_for_tx(cur, n_tx.txid)

            set_ingest_cursor(cur, cursor_key, block.height)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest Bitcoin blocks into Postgres")
    parser.add_argument("--start-height", type=int, default=None)
    parser.add_argument("--end-height", type=int, default=None)
    parser.add_argument("--max-blocks", type=int, default=10)
    parser.add_argument("--cursor-key", type=str, default="bitcoin_main")
    parser.add_argument("--schema-path", type=str, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = Settings()
    rpc = BitcoinRpcClient(
        url=settings.bitcoin_rpc_url,
        user=settings.bitcoin_rpc_user,
        password=settings.bitcoin_rpc_password,
    )

    root = Path(__file__).resolve().parents[3]
    schema_path = Path(args.schema_path) if args.schema_path else root / "sql" / "001_init.sql"

    conn = connect(settings)
    try:
        apply_schema(conn, schema_path)

        chain_tip = int(rpc.call("getblockcount"))
        with conn.cursor() as cur:
            cursor_height = get_ingest_cursor(cur, args.cursor_key)

        if args.start_height is not None:
            start_height = args.start_height
        elif cursor_height is not None:
            start_height = cursor_height + 1
        else:
            start_height = max(0, chain_tip - args.max_blocks + 1)

        end_height = args.end_height if args.end_height is not None else min(chain_tip, start_height + args.max_blocks - 1)

        if start_height > end_height:
            print(f"No blocks to ingest: start={start_height}, end={end_height}")
            return

        print(f"Ingesting blocks {start_height}..{end_height} (tip={chain_tip})")
        for height in range(start_height, end_height + 1):
            ingest_block(rpc, conn, height, args.cursor_key)
            print(f"ingested height={height}")

        print("Ingestion completed")
    finally:
        conn.close()


if __name__ == "__main__":
    main()


def ingest_tx_by_txid(rpc: BitcoinRpcClient, conn, txid: str) -> bool:
    """
    Holt eine einzelne TX via RPC und ingested sie in PostgreSQL.
    Wird vom fraud_report TraceEngine als Fallback genutzt.
    Gibt True zurück wenn erfolgreich, False wenn TX nicht gefunden.
    """
    try:
        raw_tx = rpc.call("getrawtransaction", [txid, True])
    except RuntimeError:
        return False

    blockhash = raw_tx.get("blockhash")
    if not blockhash:
        return False  # unconfirmed

    verbose_block = rpc.call("getblock", [blockhash, 1])
    block_height = verbose_block["height"]
    block_time = verbose_block["time"]
    from datetime import datetime, timezone
    block_ts = datetime.fromtimestamp(block_time, tz=timezone.utc)

    from afci.db.postgres import BlockRow, TxRow, TxInputRow, TxOutputRow, tx as db_tx
    from afci.db.postgres import upsert_block, upsert_tx, upsert_tx_input, upsert_tx_output, upsert_address, link_spent_outputs_for_tx
    from afci.ingest.parser import btc_to_sats, _extract_address

    with db_tx(conn):
        with conn.cursor() as cur:
            upsert_block(cur, BlockRow(height=block_height, block_hash=blockhash, timestamp=block_ts))

            fee_sats = btc_to_sats(raw_tx.get("fee"))
            upsert_tx(cur, TxRow(txid=txid, block_height=block_height, fee_sats=fee_sats, vsize=raw_tx.get("vsize")))

            for vin_index, vin in enumerate(raw_tx.get("vin", [])):
                if "coinbase" in vin:
                    continue
                prev_txid = vin.get("txid")
                prev_vout_idx = vin.get("vout")
                prevout = _resolve_prevout(rpc, prev_txid, prev_vout_idx) if prev_txid is not None else None
                addr = prevout.get("address") if prevout else None
                amt = btc_to_sats(prevout.get("value")) if prevout else None
                if addr:
                    upsert_address(cur, addr, script_type=None)
                upsert_tx_input(cur, TxInputRow(txid=txid, vin_index=vin_index, prev_txid=prev_txid, prev_vout=prev_vout_idx, address=addr, amount_sats=amt))

            for vout in raw_tx.get("vout", []):
                spk = vout.get("scriptPubKey", {})
                addr = _extract_address(spk)
                amt = btc_to_sats(vout.get("value")) or 0
                if addr:
                    upsert_address(cur, addr, script_type=spk.get("type"))
                upsert_tx_output(cur, TxOutputRow(txid=txid, vout_index=int(vout["n"]), address=addr, script_type=spk.get("type"), amount_sats=amt))

            link_spent_outputs_for_tx(cur, txid)

    return True

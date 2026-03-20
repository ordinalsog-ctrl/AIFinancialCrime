#!/usr/bin/env python3
"""
Ingests a single Bitcoin transaction (and its block) from the local node into PostgreSQL.
Usage: python3 scripts/ingest_tx.py <txid>
"""
import os, sys, json, requests, psycopg2
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

RPC_URL  = os.environ.get("BITCOIN_RPC_URL", "http://192.168.178.93:8332")
RPC_USER = os.environ.get("BITCOIN_RPC_USER", "aifc")
RPC_PASS = os.environ.get("BITCOIN_RPC_PASSWORD", "CHANGE_ME")
DSN      = os.environ.get("POSTGRES_DSN")

def rpc(method, params=[]):
    r = requests.post(RPC_URL, json={"jsonrpc":"1.0","method":method,"params":params},
                      auth=(RPC_USER, RPC_PASS), timeout=30)
    r.raise_for_status()
    result = r.json()
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]

def ingest_tx(txid: str):
    conn = psycopg2.connect(DSN)
    cur  = conn.cursor()

    # Fetch raw TX
    raw = rpc("getrawtransaction", [txid, True])
    blockhash = raw.get("blockhash")
    if not blockhash:
        print("TX not yet confirmed in a block.")
        sys.exit(1)

    # Fetch block
    block = rpc("getblock", [blockhash, 1])
    height    = block["height"]
    blocktime = datetime.fromtimestamp(block["time"], tz=timezone.utc)

    # Insert block
    cur.execute("""
        INSERT INTO blocks (height, hash, timestamp)
        VALUES (%s, %s, %s)
        ON CONFLICT (height) DO NOTHING
    """, (height, blockhash, blocktime))

    # Calc fee (sum inputs - sum outputs) — simplified: store 0 if coinbase
    is_coinbase = "coinbase" in raw["vin"][0]
    fee_sats = 0
    vsize    = raw.get("vsize", raw.get("size", 0))

    # Insert transaction
    cur.execute("""
        INSERT INTO transactions (txid, block_height, fee_sats, vsize, first_seen)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (txid) DO NOTHING
    """, (txid, height, fee_sats, vsize, blocktime))

    # Insert outputs
    for vout in raw["vout"]:
        addresses = vout.get("scriptPubKey", {}).get("addresses") or \
                    vout.get("scriptPubKey", {}).get("address")
        if isinstance(addresses, str):
            addresses = [addresses]
        if not addresses:
            continue
        addr = addresses[0]
        amount_sats = int(round(vout["value"] * 1e8))

        # Upsert address
        cur.execute("INSERT INTO addresses (address) VALUES (%s) ON CONFLICT DO NOTHING", (addr,))

        cur.execute("""
            INSERT INTO tx_outputs (txid, vout_index, address, amount_sats)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (txid, vout["n"], addr, amount_sats))

    # Insert inputs
    if not is_coinbase:
        for idx, vin in enumerate(raw["vin"]):
            prev_txid = vin["txid"]
            prev_vout = vin["vout"]
            # Try to get input address from prev tx
            try:
                prev_raw = rpc("getrawtransaction", [prev_txid, True])
                prev_out = prev_raw["vout"][prev_vout]
                addrs = prev_out.get("scriptPubKey", {}).get("addresses") or \
                        prev_out.get("scriptPubKey", {}).get("address")
                
                if isinstance(addrs, str):
                    addrs = [addrs]
                addr = addrs[0] if addrs else None
                if addr:
                    cur.execute("INSERT INTO addresses (address) VALUES (%s) ON CONFLICT DO NOTHING", (addr,))
                amount_sats = int(round(prev_out["value"] * 1e8))
            except Exception:
                addr = None
                amount_sats = 0

            cur.execute("""
                INSERT INTO tx_inputs (txid, prev_txid, prev_vout, address, amount_sats, vin_index)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (txid, prev_txid, prev_vout, addr, amount_sats, idx))

    conn.commit()
    cur.close()
    conn.close()
    print(f"✅ Ingested TX {txid} at block {height} ({blocktime})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/ingest_tx.py <txid>")
        sys.exit(1)
    ingest_tx(sys.argv[1])

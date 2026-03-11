from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any


@dataclass
class NormalizedInput:
    vin_index: int
    prev_txid: str | None
    prev_vout: int | None
    address: str | None
    amount_sats: int | None


@dataclass
class NormalizedOutput:
    vout_index: int
    address: str | None
    script_type: str | None
    amount_sats: int


@dataclass
class NormalizedTx:
    txid: str
    fee_sats: int | None
    vsize: int | None
    inputs: list[NormalizedInput]
    outputs: list[NormalizedOutput]


@dataclass
class NormalizedBlock:
    height: int
    block_hash: str
    timestamp: datetime
    transactions: list[NormalizedTx]


def btc_to_sats(value: float | str | Decimal | int | None) -> int | None:
    if value is None:
        return None
    dec = Decimal(str(value)) * Decimal("100000000")
    return int(dec.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _extract_address(script_pub_key: dict[str, Any]) -> str | None:
    if "address" in script_pub_key:
        return script_pub_key["address"]
    addresses = script_pub_key.get("addresses")
    if isinstance(addresses, list) and addresses:
        return addresses[0]
    return None


def parse_verbose_block(
    block: dict[str, Any],
    prevout_resolver: callable,
) -> NormalizedBlock:
    txs: list[NormalizedTx] = []

    for tx in block.get("tx", []):
        inputs: list[NormalizedInput] = []
        outputs: list[NormalizedOutput] = []

        for vin_index, vin in enumerate(tx.get("vin", [])):
            if "coinbase" in vin:
                inputs.append(
                    NormalizedInput(
                        vin_index=vin_index,
                        prev_txid=None,
                        prev_vout=None,
                        address=None,
                        amount_sats=None,
                    )
                )
                continue

            prev_txid = vin.get("txid")
            prev_vout = vin.get("vout")
            prevout = prevout_resolver(prev_txid, prev_vout) if prev_txid is not None and prev_vout is not None else None
            inputs.append(
                NormalizedInput(
                    vin_index=vin_index,
                    prev_txid=prev_txid,
                    prev_vout=prev_vout,
                    address=prevout.get("address") if prevout else None,
                    amount_sats=btc_to_sats(prevout.get("value")) if prevout else None,
                )
            )

        for vout in tx.get("vout", []):
            script_pub_key = vout.get("scriptPubKey", {})
            outputs.append(
                NormalizedOutput(
                    vout_index=int(vout["n"]),
                    address=_extract_address(script_pub_key),
                    script_type=script_pub_key.get("type"),
                    amount_sats=btc_to_sats(vout.get("value")) or 0,
                )
            )

        txs.append(
            NormalizedTx(
                txid=tx["txid"],
                fee_sats=btc_to_sats(tx.get("fee")),
                vsize=tx.get("vsize"),
                inputs=inputs,
                outputs=outputs,
            )
        )

    return NormalizedBlock(
        height=int(block["height"]),
        block_hash=block["hash"],
        timestamp=datetime.fromtimestamp(int(block["time"]), tz=timezone.utc),
        transactions=txs,
    )

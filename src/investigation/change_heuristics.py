"""
AIFinancialCrime — Change Output Heuristics
============================================
Identifies which output of a Bitcoin transaction is the "change"
(returned to sender) vs the intended payment output.

Correctly identifying change outputs is critical for:
  - Following the actual payment path (not the change)
  - CIO (Common Input Ownership) cluster accuracy
  - Preventing false peeling chain detection

Heuristics implemented (in confidence order):
  H1  Script type mismatch     — change output has same script type as inputs
  H2  Round-amount payment     — payment is round, change is the remainder
  H3  Positional (output index) — change often at index 0 or last
  H4  Address reuse            — address seen in inputs = definitely change
  H5  Value heuristic          — smallest output often change (low-value remainder)
  H6  BIP69 ordering           — lexicographic output ordering = privacy-aware wallet
  H7  Unnecessary input        — if a single input could have paid, extra inputs fund change

Each heuristic returns a confidence delta. Final score ≥ 0.5 = change output.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from src.core.logging_config import get_logger

logger = get_logger("aifc.change_heuristic")


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class TxInput:
    txid: str
    vout: int
    address: str
    value_sat: int
    script_type: str   # p2pkh | p2sh | p2wpkh | p2wsh | p2tr | unknown


@dataclass
class TxOutput:
    index: int
    address: str
    value_sat: int
    script_type: str   # p2pkh | p2sh | p2wpkh | p2wsh | p2tr | unknown
    is_op_return: bool = False


@dataclass
class ChangeAnalysis:
    output_index: int
    address: str
    value_sat: float
    change_probability: float         # 0.0 – 1.0
    payment_probability: float        # 1 - change_probability
    heuristics_fired: list[str]
    heuristics_failed: list[str]
    confidence_label: str             # "certain" | "likely" | "possible" | "unlikely"

    @property
    def value_btc(self) -> float:
        return self.value_sat / 1e8

    @property
    def is_change(self) -> bool:
        return self.change_probability >= 0.5

    def __str__(self) -> str:
        direction = "CHANGE" if self.is_change else "PAYMENT"
        return (f"Output[{self.output_index}] {self.address[:10]}… "
                f"{self.value_btc:.8f} BTC → {direction} "
                f"({self.confidence_label}, p={self.change_probability:.2f})")


@dataclass
class TxChangeResult:
    txid: str
    inputs: list[TxInput]
    outputs: list[TxOutput]
    analyses: list[ChangeAnalysis]

    @property
    def most_likely_change(self) -> Optional[ChangeAnalysis]:
        changes = [a for a in self.analyses if a.is_change]
        if not changes:
            return None
        return max(changes, key=lambda a: a.change_probability)

    @property
    def most_likely_payment(self) -> Optional[ChangeAnalysis]:
        payments = [a for a in self.analyses if not a.is_change]
        if not payments:
            return None
        return min(payments, key=lambda a: a.change_probability)

    def format_summary(self) -> str:
        lines = [f"TX {self.txid[:16]}… — {len(self.inputs)} Inputs, {len(self.outputs)} Outputs"]
        for a in self.analyses:
            lines.append(f"  {a}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Heuristics Engine
# ---------------------------------------------------------------------------

# BTC satoshi denominations — "round" amounts
ROUND_SAT_VALUES = {
    1_000_000,          #  0.01 BTC
    5_000_000,          #  0.05 BTC
    10_000_000,         #  0.10 BTC
    50_000_000,         #  0.50 BTC
    100_000_000,        #  1.00 BTC
    500_000_000,        #  5.00 BTC
    1_000_000_000,      # 10.00 BTC
    5_000_000_000,      # 50.00 BTC
    10_000_000_000,     # 100.0 BTC
}

ROUND_BTC_TOLERANCE = 0.0001   # ±0.0001 BTC still considered "round"


def _is_round_amount(value_sat: int) -> bool:
    """Check if a satoshi value is a round BTC amount."""
    value_btc = value_sat / 1e8
    for round_sat in ROUND_SAT_VALUES:
        if abs(value_sat - round_sat) <= ROUND_BTC_TOLERANCE * 1e8:
            return True
    # Also check round BTC: 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0 etc.
    for multiplier in [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]:
        if abs(value_btc % multiplier) < ROUND_BTC_TOLERANCE:
            return True
    return False


def _is_bip69_ordered(outputs: list[TxOutput]) -> bool:
    """Check if outputs are BIP69 sorted (by value, then script)."""
    values = [o.value_sat for o in outputs]
    return values == sorted(values)


class ChangeOutputHeuristics:
    """
    Analyses a Bitcoin transaction to identify change vs payment outputs.

    Usage:
        engine = ChangeOutputHeuristics()
        result = engine.analyse(txid, inputs, outputs)
        change = result.most_likely_change
        payment = result.most_likely_payment
    """

    def analyse(
        self,
        txid: str,
        inputs: list[TxInput],
        outputs: list[TxOutput],
    ) -> TxChangeResult:
        """
        Run all heuristics and return per-output ChangeAnalysis.
        """
        # Filter OP_RETURN outputs — never change
        real_outputs = [o for o in outputs if not o.is_op_return]

        if not real_outputs:
            return TxChangeResult(txid=txid, inputs=inputs, outputs=outputs, analyses=[])

        # Precompute
        input_addresses = {inp.address for inp in inputs}
        input_script_types = {inp.script_type for inp in inputs if inp.script_type != "unknown"}
        total_input_sat = sum(inp.value_sat for inp in inputs)
        output_values = [o.value_sat for o in real_outputs]
        min_output = min(output_values)
        max_output = max(output_values)

        bip69 = _is_bip69_ordered(real_outputs)

        analyses = []
        for output in real_outputs:
            score = 0.0
            fired = []
            failed = []

            # H1: Script type match (inputs and this output have same script type)
            if output.script_type in input_script_types:
                score += 0.20
                fired.append("H1_script_type_match")
            else:
                failed.append("H1_script_type_mismatch")

            # H2: Round amount payment heuristic
            # If this output is round → likely payment, other output is change
            if _is_round_amount(output.value_sat):
                score -= 0.30   # round = more likely payment, not change
                failed.append("H2_round_amount_payment")
            else:
                # Non-round output = more likely change
                # Check if any OTHER output is round
                other_round = any(_is_round_amount(o.value_sat)
                                  for o in real_outputs if o.index != output.index)
                if other_round:
                    score += 0.25
                    fired.append("H2_round_amount_sibling")

            # H3: Address reuse — if input address == this output address: CERTAIN change
            if output.address in input_addresses:
                score += 0.60
                fired.append("H3_address_reuse")

            # H4: Positional — outputs at index 0 or last index are statistically more often change
            if output.index == 0 or output.index == len(real_outputs) - 1:
                score += 0.05
                fired.append("H4_positional_edge")

            # H5: Value heuristic — smallest output is often change (remainder)
            if len(real_outputs) == 2:
                if output.value_sat == min_output:
                    score += 0.10
                    fired.append("H5_smallest_output")
                else:
                    score -= 0.05
                    failed.append("H5_not_smallest")

            # H6: BIP69 (privacy-aware ordering) — reduces positional signal
            if bip69:
                score -= 0.05   # BIP69 wallets deliberately obscure change position
                failed.append("H6_bip69_ordering")

            # H7: Unnecessary input heuristic
            # If total inputs >> largest output, the excess is likely change at this output
            if len(inputs) > 1:
                largest_output = max_output
                if total_input_sat > largest_output * 1.5 and output.value_sat < largest_output:
                    score += 0.10
                    fired.append("H7_unnecessary_input_remainder")

            # Clamp
            score = max(0.0, min(1.0, score))

            # Confidence label
            if score >= 0.80:
                conf = "certain"
            elif score >= 0.55:
                conf = "likely"
            elif score >= 0.35:
                conf = "possible"
            else:
                conf = "unlikely"

            analyses.append(ChangeAnalysis(
                output_index=output.index,
                address=output.address,
                value_sat=output.value_sat,
                change_probability=score,
                payment_probability=1.0 - score,
                heuristics_fired=fired,
                heuristics_failed=failed,
                confidence_label=conf,
            ))

        # Normalize: in a 2-output TX, probabilities should roughly sum to ~1
        # (one is change, one is payment)
        if len(analyses) == 2:
            a, b = analyses
            total = a.change_probability + b.change_probability
            if total > 0:
                a.change_probability = round(a.change_probability / total, 3)
                b.change_probability = round(b.change_probability / total, 3)
                a.payment_probability = 1.0 - a.change_probability
                b.payment_probability = 1.0 - b.change_probability

        logger.debug(
            "change_analysis_complete",
            txid=txid[:16],
            outputs=len(analyses),
            change_idx=next((a.output_index for a in analyses if a.is_change), None),
        )

        return TxChangeResult(
            txid=txid,
            inputs=inputs,
            outputs=outputs,
            analyses=analyses,
        )

    def annotate_hop_chain(self, hop_chain: list, raw_tx_data: dict) -> list:
        """
        Post-process a hop chain to mark which outputs are change.
        raw_tx_data: dict of txid → {"inputs": [...], "outputs": [...]}

        Returns the hop_chain with is_change_output set correctly.
        """
        for hop in hop_chain:
            txid = getattr(hop, "txid", "")
            if txid not in raw_tx_data:
                continue
            tx = raw_tx_data[txid]
            inputs = [TxInput(**i) for i in tx.get("inputs", [])]
            outputs = [TxOutput(**o) for o in tx.get("outputs", [])]
            result = self.analyse(txid, inputs, outputs)
            change = result.most_likely_change
            if change and hasattr(hop, "is_change_output"):
                hop_out_addr = getattr(hop, "to_address", "")
                hop.is_change_output = (change.address == hop_out_addr)
        return hop_chain


# ---------------------------------------------------------------------------
# Utility: parse raw Blockstream TX into heuristic input format
# ---------------------------------------------------------------------------

def parse_blockstream_tx(tx_json: dict) -> tuple[list[TxInput], list[TxOutput]]:
    """
    Convert Blockstream API TX response into TxInput/TxOutput lists.

    tx_json: response from https://blockstream.info/api/tx/{txid}
    """
    inputs = []
    for vin in tx_json.get("vin", []):
        prev = vin.get("prevout", {})
        addr = prev.get("scriptpubkey_address", "")
        script_type = _normalize_script_type(prev.get("scriptpubkey_type", ""))
        inputs.append(TxInput(
            txid=vin.get("txid", ""),
            vout=vin.get("vout", 0),
            address=addr,
            value_sat=prev.get("value", 0),
            script_type=script_type,
        ))

    outputs = []
    for idx, vout in enumerate(tx_json.get("vout", [])):
        addr = vout.get("scriptpubkey_address", "")
        script_type = _normalize_script_type(vout.get("scriptpubkey_type", ""))
        is_op = vout.get("scriptpubkey_type", "") == "op_return"
        outputs.append(TxOutput(
            index=idx,
            address=addr,
            value_sat=vout.get("value", 0),
            script_type=script_type,
            is_op_return=is_op,
        ))

    return inputs, outputs


def _normalize_script_type(raw: str) -> str:
    mapping = {
        "p2pkh": "p2pkh",
        "p2sh": "p2sh",
        "v0_p2wpkh": "p2wpkh",
        "p2wpkh": "p2wpkh",
        "v0_p2wsh": "p2wsh",
        "p2wsh": "p2wsh",
        "v1_p2tr": "p2tr",
        "p2tr": "p2tr",
        "op_return": "op_return",
    }
    return mapping.get(raw.lower(), "unknown")

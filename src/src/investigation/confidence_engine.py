"""
Confidence Engine — Deterministic UTXO Tracing with Forensic Evidence Chain

Design principles:
- Every conclusion is backed by explicit, verifiable evidence
- Confidence levels are rule-based, not probabilistic
- All evidence is reproducible by independent experts
- No speculation enters the official report (L3/L4 are flagged clearly)

Confidence Levels:
  L1 — Verified Fact       : Mathematically provable on-chain (direct UTXO link)
  L2 — High Confidence     : Forensically accepted methodology (amount+temporal match,
                             known exchange attribution)
  L3 — Indicative          : Observable pattern, not proof (delayed match, split)
  L4 — Speculative         : Heuristic only (CIO clustering) — never in official report
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ConfidenceLevel(enum.IntEnum):
    L1_VERIFIED_FACT    = 1   # Direct UTXO linkage — mathematically proven
    L2_HIGH_CONFIDENCE  = 2   # Forensically accepted methodology
    L3_INDICATIVE       = 3   # Observable pattern — include with caveat
    L4_SPECULATIVE      = 4   # Heuristic — internal use only, never in report


class TracingMethod(str, enum.Enum):
    UTXO_DIRECT          = "UTXO_DIRECT"           # Output used as input in next TX
    AMOUNT_EXACT_MATCH   = "AMOUNT_EXACT_MATCH"    # Same amount ± miner fee, same block/window
    AMOUNT_TEMPORAL      = "AMOUNT_TEMPORAL"        # Same amount, time-delayed
    AMOUNT_SPLIT         = "AMOUNT_SPLIT"           # Input split into matching outputs
    EXCHANGE_ATTRIBUTION = "EXCHANGE_ATTRIBUTION"   # Address in known exchange database
    OFAC_MATCH           = "OFAC_MATCH"             # Address on OFAC SDN list
    CIO_HEURISTIC        = "CIO_HEURISTIC"          # Common-input-ownership (L4 only)


REPORT_ELIGIBLE_LEVELS = {
    ConfidenceLevel.L1_VERIFIED_FACT,
    ConfidenceLevel.L2_HIGH_CONFIDENCE,
    ConfidenceLevel.L3_INDICATIVE,   # included with explicit caveat
}

OFFICIAL_REPORT_LEVELS = {
    ConfidenceLevel.L1_VERIFIED_FACT,
    ConfidenceLevel.L2_HIGH_CONFIDENCE,
}


# ---------------------------------------------------------------------------
# Evidence Items — every claim is backed by at least one
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    """
    A single verifiable piece of evidence.
    Every field must be independently reproducible.
    """
    evidence_type: str
    description: str
    source: str                          # e.g. "Bitcoin Blockchain, Block 835241"
    verifiable_at: Optional[str] = None  # public block explorer URL
    timestamp_utc: Optional[datetime] = None
    raw_value: Optional[str] = None      # raw on-chain data point

    def to_dict(self) -> dict:
        return {
            "evidence_type": self.evidence_type,
            "description": self.description,
            "source": self.source,
            "verifiable_at": self.verifiable_at,
            "timestamp_utc": self.timestamp_utc.isoformat() if self.timestamp_utc else None,
            "raw_value": self.raw_value,
        }


# ---------------------------------------------------------------------------
# Tracing Hop — one step in the chain of custody
# ---------------------------------------------------------------------------

@dataclass
class TracingHop:
    """
    Represents one hop in the UTXO tracing chain.
    Each hop has a method, confidence level, and full evidence list.
    """
    hop_index: int
    from_txid: str
    to_txid: str
    from_address: Optional[str]
    to_address: Optional[str]
    amount_btc: Decimal
    method: TracingMethod
    confidence: ConfidenceLevel
    evidence: list[EvidenceItem] = field(default_factory=list)
    block_height_from: Optional[int] = None
    block_height_to: Optional[int] = None
    timestamp_from: Optional[datetime] = None
    timestamp_to: Optional[datetime] = None
    time_delta_seconds: Optional[int] = None
    exchange_name: Optional[str] = None       # set if EXCHANGE_ATTRIBUTION
    exchange_source: Optional[str] = None     # e.g. "WalletExplorer", "OFAC"
    caveat: Optional[str] = None              # shown in report for L3

    @property
    def is_report_eligible(self) -> bool:
        return self.confidence in REPORT_ELIGIBLE_LEVELS

    @property
    def is_official_report_eligible(self) -> bool:
        return self.confidence in OFFICIAL_REPORT_LEVELS

    def to_dict(self) -> dict:
        return {
            "hop_index": self.hop_index,
            "from_txid": self.from_txid,
            "to_txid": self.to_txid,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "amount_btc": str(self.amount_btc),
            "method": self.method.value,
            "confidence_level": self.confidence.value,
            "confidence_label": self.confidence.name,
            "is_official_report_eligible": self.is_official_report_eligible,
            "block_height_from": self.block_height_from,
            "block_height_to": self.block_height_to,
            "timestamp_from": self.timestamp_from.isoformat() if self.timestamp_from else None,
            "timestamp_to": self.timestamp_to.isoformat() if self.timestamp_to else None,
            "time_delta_seconds": self.time_delta_seconds,
            "exchange_name": self.exchange_name,
            "exchange_source": self.exchange_source,
            "caveat": self.caveat,
            "evidence": [e.to_dict() for e in self.evidence],
        }


# ---------------------------------------------------------------------------
# Confidence Rules — explicit, auditable, extensible
# ---------------------------------------------------------------------------

# Temporal thresholds (seconds)
THRESHOLD_EXACT_WINDOW_SEC    = 600      # 10 min  → L2 exact match
THRESHOLD_HIGH_CONF_SEC       = 21_600  # 6 hours → L2 temporal (covers delayed laundering)
THRESHOLD_INDICATIVE_SEC      = 172_800 # 48 hours → L3

# Amount tolerance (to account for miner fees)
MINER_FEE_TOLERANCE_BTC = Decimal("0.001")  # 100k sats — conservative


def classify_temporal_hop(
    amount_in: Decimal,
    amount_out: Decimal,
    time_delta_seconds: int,
    block_delta: int,
) -> tuple[ConfidenceLevel, TracingMethod, Optional[str]]:
    """
    Classify a temporal amount-match hop.
    Returns (confidence, method, caveat_text).

    Rules:
    - Amount must be within MINER_FEE_TOLERANCE_BTC
    - Time delta drives confidence level
    """
    amount_diff = abs(amount_in - amount_out)
    caveat = None

    if amount_diff > MINER_FEE_TOLERANCE_BTC:
        # Amount mismatch too large — not a clean match
        return ConfidenceLevel.L4_SPECULATIVE, TracingMethod.CIO_HEURISTIC, \
               f"Betragsdifferenz {amount_diff} BTC übersteigt Toleranzgrenze — kein valider Match"

    if time_delta_seconds <= THRESHOLD_EXACT_WINDOW_SEC:
        return ConfidenceLevel.L2_HIGH_CONFIDENCE, TracingMethod.AMOUNT_EXACT_MATCH, None

    elif time_delta_seconds <= THRESHOLD_HIGH_CONF_SEC:
        caveat = (
            f"Zeitversatz {time_delta_seconds // 60} Minuten — "
            "forensisch anerkannte Methodik, zeitliche Verzögerung dokumentiert"
        )
        return ConfidenceLevel.L2_HIGH_CONFIDENCE, TracingMethod.AMOUNT_TEMPORAL, caveat

    elif time_delta_seconds <= THRESHOLD_INDICATIVE_SEC:
        caveat = (
            f"Zeitversatz {time_delta_seconds // 3600:.1f} Stunden — "
            "als Hinweis dokumentiert, kein direkter Beweis"
        )
        return ConfidenceLevel.L3_INDICATIVE, TracingMethod.AMOUNT_TEMPORAL, caveat

    else:
        caveat = (
            f"Zeitversatz {time_delta_seconds // 3600:.0f} Stunden — "
            "spekulativ, nicht im offiziellen Report"
        )
        return ConfidenceLevel.L4_SPECULATIVE, TracingMethod.AMOUNT_TEMPORAL, caveat


def classify_split_hop(
    amount_in: Decimal,
    amounts_out: list[Decimal],
    time_delta_seconds: int,
) -> tuple[ConfidenceLevel, TracingMethod, Optional[str]]:
    """
    Classify a split transaction:
    e.g. 10 BTC in → 5 BTC + 5 BTC out (or 3+7, etc.)

    L2 if sum matches within tolerance and time window is short.
    L3 if delayed.
    """
    total_out = sum(amounts_out)
    amount_diff = abs(amount_in - total_out)
    caveat = None

    if amount_diff > MINER_FEE_TOLERANCE_BTC:
        return ConfidenceLevel.L4_SPECULATIVE, TracingMethod.AMOUNT_SPLIT, \
               f"Summendifferenz {amount_diff} BTC — kein valider Split-Match"

    split_description = " + ".join(f"{a} BTC" for a in amounts_out)
    caveat = (
        f"Aufspaltung: {amount_in} BTC → {split_description} "
        f"(Summe ± Miner Fee). Zeitversatz: {time_delta_seconds}s."
    )

    if time_delta_seconds <= THRESHOLD_HIGH_CONF_SEC:
        return ConfidenceLevel.L2_HIGH_CONFIDENCE, TracingMethod.AMOUNT_SPLIT, caveat
    else:
        caveat += " Zeitversatz > 1h — als Hinweis gewertet."
        return ConfidenceLevel.L3_INDICATIVE, TracingMethod.AMOUNT_SPLIT, caveat


# ---------------------------------------------------------------------------
# Hop Builders — factory functions for clean, consistent hop creation
# ---------------------------------------------------------------------------

def build_direct_utxo_hop(
    hop_index: int,
    from_txid: str,
    to_txid: str,
    from_address: Optional[str],
    to_address: Optional[str],
    amount_btc: Decimal,
    block_height_from: int,
    block_height_to: int,
    timestamp_from: datetime,
    timestamp_to: datetime,
) -> TracingHop:
    """
    L1: Output of from_txid used directly as input of to_txid.
    This is mathematically proven by the UTXO model.
    """
    time_delta = int((timestamp_to - timestamp_from).total_seconds())

    evidence = [
        EvidenceItem(
            evidence_type="UTXO_DIRECT_LINK",
            description=(
                f"Output von Transaktion {from_txid[:16]}... "
                f"direkt als Input in Transaktion {to_txid[:16]}... verwendet. "
                f"Mathematisch eindeutig durch das Bitcoin UTXO-Modell belegt."
            ),
            source=f"Bitcoin Blockchain, Blöcke {block_height_from}–{block_height_to}",
            verifiable_at=f"https://blockstream.info/tx/{to_txid}",
            timestamp_utc=timestamp_to,
            raw_value=f"prevout: {from_txid}",
        )
    ]

    return TracingHop(
        hop_index=hop_index,
        from_txid=from_txid,
        to_txid=to_txid,
        from_address=from_address,
        to_address=to_address,
        amount_btc=amount_btc,
        method=TracingMethod.UTXO_DIRECT,
        confidence=ConfidenceLevel.L1_VERIFIED_FACT,
        evidence=evidence,
        block_height_from=block_height_from,
        block_height_to=block_height_to,
        timestamp_from=timestamp_from,
        timestamp_to=timestamp_to,
        time_delta_seconds=time_delta,
    )


def build_temporal_hop(
    hop_index: int,
    from_txid: str,
    to_txid: str,
    from_address: Optional[str],
    to_address: Optional[str],
    amount_in: Decimal,
    amounts_out: list[Decimal],
    block_height_from: int,
    block_height_to: int,
    timestamp_from: datetime,
    timestamp_to: datetime,
) -> TracingHop:
    """
    L2/L3: Amount-matching with temporal correlation.
    Handles exact, delayed, and split scenarios.
    """
    time_delta = int((timestamp_to - timestamp_from).total_seconds())
    is_split = len(amounts_out) > 1
    amount_out = sum(amounts_out)

    if is_split:
        confidence, method, caveat = classify_split_hop(
            amount_in, amounts_out, time_delta
        )
    else:
        confidence, method, caveat = classify_temporal_hop(
            amount_in, amounts_out[0], time_delta, block_height_to - block_height_from
        )

    amount_str = " + ".join(f"{a} BTC" for a in amounts_out)
    evidence = [
        EvidenceItem(
            evidence_type="AMOUNT_TEMPORAL_MATCH",
            description=(
                f"Eingang: {amount_in} BTC um {timestamp_from.strftime('%H:%M:%S')} UTC "
                f"(Block {block_height_from}). "
                f"Ausgang: {amount_str} um {timestamp_to.strftime('%H:%M:%S')} UTC "
                f"(Block {block_height_to}). "
                f"Zeitversatz: {time_delta}s. "
                f"Betragsdifferenz: {abs(amount_in - amount_out):.8f} BTC."
            ),
            source=f"Bitcoin Blockchain, Blöcke {block_height_from}–{block_height_to}",
            verifiable_at=f"https://blockstream.info/tx/{to_txid}",
            timestamp_utc=timestamp_to,
            raw_value=f"in={amount_in} out={amount_out} delta_sec={time_delta}",
        )
    ]

    return TracingHop(
        hop_index=hop_index,
        from_txid=from_txid,
        to_txid=to_txid,
        from_address=from_address,
        to_address=to_address,
        amount_btc=amount_out,
        method=method,
        confidence=confidence,
        evidence=evidence,
        block_height_from=block_height_from,
        block_height_to=block_height_to,
        timestamp_from=timestamp_from,
        timestamp_to=timestamp_to,
        time_delta_seconds=time_delta,
        caveat=caveat,
    )


def build_exchange_hop(
    hop_index: int,
    txid: str,
    address: str,
    amount_btc: Decimal,
    exchange_name: str,
    exchange_source: str,
    block_height: int,
    timestamp: datetime,
    previous_hop: TracingHop,
) -> TracingHop:
    """
    L2: Address identified in known exchange attribution database.
    Source must be explicitly named for report credibility.
    """
    evidence = [
        EvidenceItem(
            evidence_type="EXCHANGE_ATTRIBUTION",
            description=(
                f"Adresse {address} ist als Deposit-Adresse von "
                f"{exchange_name} klassifiziert. "
                f"Quelle: {exchange_source}."
            ),
            source=exchange_source,
            verifiable_at=f"https://blockstream.info/address/{address}",
            timestamp_utc=timestamp,
            raw_value=f"address={address} exchange={exchange_name}",
        )
    ]

    return TracingHop(
        hop_index=hop_index,
        from_txid=previous_hop.to_txid,
        to_txid=txid,
        from_address=previous_hop.to_address,
        to_address=address,
        amount_btc=amount_btc,
        method=TracingMethod.EXCHANGE_ATTRIBUTION,
        confidence=ConfidenceLevel.L2_HIGH_CONFIDENCE,
        evidence=evidence,
        block_height_from=previous_hop.block_height_to,
        block_height_to=block_height,
        timestamp_from=previous_hop.timestamp_to,
        timestamp_to=timestamp,
        exchange_name=exchange_name,
        exchange_source=exchange_source,
    )


# ---------------------------------------------------------------------------
# Investigation Chain — the full tracing result
# ---------------------------------------------------------------------------

@dataclass
class InvestigationChain:
    """
    Complete forensic tracing chain for one fraud case.
    """
    case_id: str
    fraud_txid: str
    fraud_address: str
    fraud_amount_btc: Decimal
    fraud_timestamp: datetime
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    hops: list[TracingHop] = field(default_factory=list)

    def add_hop(self, hop: TracingHop) -> None:
        self.hops.append(hop)

    @property
    def official_report_hops(self) -> list[TracingHop]:
        """Only L1 and L2 hops — safe for official submission."""
        return [h for h in self.hops if h.is_official_report_eligible]

    @property
    def exchange_hits(self) -> list[TracingHop]:
        """All hops that identified an exchange."""
        return [h for h in self.hops if h.exchange_name is not None]

    @property
    def minimum_confidence(self) -> Optional[ConfidenceLevel]:
        """Weakest link in the official chain."""
        official = self.official_report_hops
        if not official:
            return None
        return max(h.confidence for h in official)

    @property
    def chain_summary(self) -> str:
        """Human-readable chain summary for report header."""
        lines = [
            f"Fraud TX: {self.fraud_txid}",
            f"Betrag: {self.fraud_amount_btc} BTC",
            f"Zeitpunkt: {self.fraud_timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Analysierte Hops (gesamt): {len(self.hops)}",
            f"Hops im offiziellen Report (L1+L2): {len(self.official_report_hops)}",
        ]
        if self.exchange_hits:
            for hit in self.exchange_hits:
                lines.append(
                    f"⚠ Exchange identifiziert: {hit.exchange_name} "
                    f"(Adresse: {hit.to_address}, Quelle: {hit.exchange_source})"
                )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "fraud_txid": self.fraud_txid,
            "fraud_address": self.fraud_address,
            "fraud_amount_btc": str(self.fraud_amount_btc),
            "fraud_timestamp": self.fraud_timestamp.isoformat(),
            "created_at": self.created_at.isoformat(),
            "chain_summary": self.chain_summary,
            "minimum_confidence_in_chain": self.minimum_confidence.name if self.minimum_confidence else None,
            "exchange_hits": [h.exchange_name for h in self.exchange_hits],
            "hops": [h.to_dict() for h in self.hops],
            "official_report_hop_count": len(self.official_report_hops),
        }

"""
Tests for the Confidence Engine.
Each test documents a real forensic scenario.
"""

import pytest
from decimal import Decimal
from datetime import datetime, timezone, timedelta

from src.investigation.confidence_engine import (
    ConfidenceLevel,
    TracingMethod,
    InvestigationChain,
    build_direct_utxo_hop,
    build_temporal_hop,
    build_exchange_hop,
    classify_temporal_hop,
    classify_split_hop,
    MINER_FEE_TOLERANCE_BTC,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

T0 = datetime(2024, 3, 13, 10, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(minutes=10)
T2 = T0 + timedelta(hours=2)
T3 = T0 + timedelta(hours=25)

FRAUD_TXID  = "aaaa" * 16
HOP1_TXID   = "bbbb" * 16
HOP2_TXID   = "cccc" * 16
EXCHANGE_TX = "dddd" * 16

FRAUD_ADDR   = "1FraudAddressXXXXXXXXXXXXXXXXXXXX"
WALLET1_ADDR = "1Wallet1XXXXXXXXXXXXXXXXXXXXXXXXXX"
WALLET2_ADDR = "1Wallet2XXXXXXXXXXXXXXXXXXXXXXXXXX"
BINANCE_ADDR = "3BinanceDepositXXXXXXXXXXXXXXXXXX"

AMOUNT_10 = Decimal("10.0")
AMOUNT_5  = Decimal("5.0")

# ---------------------------------------------------------------------------
# Scenario 1: Direct UTXO — L1
# ---------------------------------------------------------------------------

def test_direct_utxo_is_l1():
    """
    Fraud TX sendet 10 BTC an Wallet 1.
    Wallet 1 verwendet exakt diesen Output als Input in nächster TX.
    → L1 Verified Fact.
    """
    hop = build_direct_utxo_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_btc=AMOUNT_10,
        block_height_from=835241,
        block_height_to=835242,
        timestamp_from=T0,
        timestamp_to=T0 + timedelta(minutes=1),
    )

    assert hop.confidence == ConfidenceLevel.L1_VERIFIED_FACT
    assert hop.method == TracingMethod.UTXO_DIRECT
    assert hop.is_official_report_eligible
    assert len(hop.evidence) == 1
    assert "UTXO_DIRECT_LINK" in hop.evidence[0].evidence_type
    assert "blockstream.info" in hop.evidence[0].verifiable_at


# ---------------------------------------------------------------------------
# Scenario 2: Exact amount match within 10 min window — L2
# ---------------------------------------------------------------------------

def test_exact_amount_match_within_window_is_l2():
    """
    10:00 Eingang 10 BTC. 10:10 Ausgang 10 BTC.
    Gleiche Wallet, hohe Transaktionsrate (Money Laundering wallet).
    → L2 Amount Exact Match.
    """
    hop = build_temporal_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_in=AMOUNT_10,
        amounts_out=[AMOUNT_10],
        block_height_from=835241,
        block_height_to=835243,
        timestamp_from=T0,
        timestamp_to=T1,
    )

    assert hop.confidence == ConfidenceLevel.L2_HIGH_CONFIDENCE
    assert hop.method == TracingMethod.AMOUNT_EXACT_MATCH
    assert hop.is_official_report_eligible
    assert hop.time_delta_seconds == 600
    assert hop.caveat is None  # clean match — no caveat needed


# ---------------------------------------------------------------------------
# Scenario 3: Same amount, 2-hour delay — L2 with caveat
# ---------------------------------------------------------------------------

def test_delayed_match_one_hour_is_l2_with_caveat():
    """
    10:00 Eingang 10 BTC. 12:00 Ausgang 10 BTC.
    Zeitversatz 2h — noch L2 aber mit dokumentiertem Caveat.
    """
    hop = build_temporal_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_in=AMOUNT_10,
        amounts_out=[AMOUNT_10],
        block_height_from=835241,
        block_height_to=835253,
        timestamp_from=T0,
        timestamp_to=T2,
    )

    assert hop.confidence == ConfidenceLevel.L2_HIGH_CONFIDENCE
    assert hop.method == TracingMethod.AMOUNT_TEMPORAL
    assert hop.caveat is not None
    assert "Zeitversatz" in hop.caveat


# ---------------------------------------------------------------------------
# Scenario 4: Same amount, 25-hour delay — L3
# ---------------------------------------------------------------------------

def test_delayed_match_23h_is_l3():
    """
    10:00 Eingang 10 BTC. 23h später Ausgang 10 BTC.
    Zeitversatz 23h (< 24h Schwelle) → L3 Indicative, mit Caveat.
    """
    T_23h = T0 + timedelta(hours=23)
    hop = build_temporal_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_in=AMOUNT_10,
        amounts_out=[AMOUNT_10],
        block_height_from=835241,
        block_height_to=835385,
        timestamp_from=T0,
        timestamp_to=T_23h,
    )

    assert hop.confidence == ConfidenceLevel.L3_INDICATIVE
    assert not hop.is_official_report_eligible
    assert hop.caveat is not None


def test_very_delayed_match_25h_is_l4():
    """
    10:00 Eingang 10 BTC. 25h später Ausgang 10 BTC.
    Zeitversatz 25h (> 24h Schwelle) → L4 Speculative.
    """
    hop = build_temporal_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_in=AMOUNT_10,
        amounts_out=[AMOUNT_10],
        block_height_from=835241,
        block_height_to=835385,
        timestamp_from=T0,
        timestamp_to=T3,
    )

    assert hop.confidence == ConfidenceLevel.L4_SPECULATIVE
    assert not hop.is_report_eligible


# ---------------------------------------------------------------------------
# Scenario 5: Split transaction 10 BTC → 5+5 BTC — L2
# ---------------------------------------------------------------------------

def test_split_transaction_is_l2():
    """
    10:00 Eingang 10 BTC. 10:05 Ausgang 5 BTC + 5 BTC.
    Aufspaltung innerhalb Zeitfenster → L2 mit Caveat.
    """
    hop = build_temporal_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_in=AMOUNT_10,
        amounts_out=[AMOUNT_5, AMOUNT_5],
        block_height_from=835241,
        block_height_to=835242,
        timestamp_from=T0,
        timestamp_to=T0 + timedelta(minutes=5),
    )

    assert hop.confidence == ConfidenceLevel.L2_HIGH_CONFIDENCE
    assert hop.method == TracingMethod.AMOUNT_SPLIT
    assert hop.is_official_report_eligible
    assert hop.caveat is not None
    assert "Aufspaltung" in hop.caveat


# ---------------------------------------------------------------------------
# Scenario 6: Exchange attribution — L2
# ---------------------------------------------------------------------------

def test_exchange_attribution_is_l2():
    """
    Wallet 2 ist als Binance Deposit Address klassifiziert.
    → L2 High Confidence, Exchange-Name im Report.
    """
    prev_hop = build_direct_utxo_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_btc=AMOUNT_10,
        block_height_from=835241,
        block_height_to=835242,
        timestamp_from=T0,
        timestamp_to=T1,
    )

    exchange_hop = build_exchange_hop(
        hop_index=2,
        txid=EXCHANGE_TX,
        address=BINANCE_ADDR,
        amount_btc=AMOUNT_10,
        exchange_name="Binance",
        exchange_source="WalletExplorer.com",
        block_height=835245,
        timestamp=T1 + timedelta(minutes=5),
        previous_hop=prev_hop,
    )

    assert exchange_hop.confidence == ConfidenceLevel.L2_HIGH_CONFIDENCE
    assert exchange_hop.method == TracingMethod.EXCHANGE_ATTRIBUTION
    assert exchange_hop.exchange_name == "Binance"
    assert exchange_hop.is_official_report_eligible
    assert "WalletExplorer" in exchange_hop.evidence[0].source


# ---------------------------------------------------------------------------
# Scenario 7: Full chain — fraud → wallet → exchange
# ---------------------------------------------------------------------------

def test_full_investigation_chain():
    """
    Vollständige Kette: Fraud TX → Wallet 1 (direkt) → Binance (Attribution).
    Prüft: official_report_hops, exchange_hits, chain_summary.
    """
    chain = InvestigationChain(
        case_id="CASE-2024-001",
        fraud_txid=FRAUD_TXID,
        fraud_address=FRAUD_ADDR,
        fraud_amount_btc=AMOUNT_10,
        fraud_timestamp=T0,
    )

    hop1 = build_direct_utxo_hop(
        hop_index=1,
        from_txid=FRAUD_TXID,
        to_txid=HOP1_TXID,
        from_address=FRAUD_ADDR,
        to_address=WALLET1_ADDR,
        amount_btc=AMOUNT_10,
        block_height_from=835241,
        block_height_to=835242,
        timestamp_from=T0,
        timestamp_to=T1,
    )

    hop2 = build_exchange_hop(
        hop_index=2,
        txid=EXCHANGE_TX,
        address=BINANCE_ADDR,
        amount_btc=AMOUNT_10,
        exchange_name="Binance",
        exchange_source="WalletExplorer.com",
        block_height=835245,
        timestamp=T1 + timedelta(minutes=5),
        previous_hop=hop1,
    )

    chain.add_hop(hop1)
    chain.add_hop(hop2)

    assert len(chain.official_report_hops) == 2
    assert len(chain.exchange_hits) == 1
    assert chain.exchange_hits[0].exchange_name == "Binance"
    assert "Binance" in chain.chain_summary
    assert chain.minimum_confidence == ConfidenceLevel.L2_HIGH_CONFIDENCE

    # Serialization check
    d = chain.to_dict()
    assert d["official_report_hop_count"] == 2
    assert "Binance" in d["exchange_hits"]


# ---------------------------------------------------------------------------
# Scenario 8: Amount mismatch → speculative
# ---------------------------------------------------------------------------

def test_large_amount_mismatch_is_speculative():
    """
    Eingang 10 BTC. Ausgang 9 BTC. Differenz 1 BTC > Toleranz.
    → L4 Speculative — nicht in Report.
    """
    confidence, method, caveat = classify_temporal_hop(
        amount_in=Decimal("10.0"),
        amount_out=Decimal("9.0"),
        time_delta_seconds=60,
        block_delta=1,
    )

    assert confidence == ConfidenceLevel.L4_SPECULATIVE
    assert caveat is not None


# ---------------------------------------------------------------------------
# Scenario 9: Miner fee within tolerance → still L2
# ---------------------------------------------------------------------------

def test_miner_fee_within_tolerance_is_l2():
    """
    Eingang 10.0 BTC. Ausgang 9.9995 BTC.
    Differenz 0.0005 BTC < Toleranz (0.001 BTC) → valider Match.
    """
    confidence, method, caveat = classify_temporal_hop(
        amount_in=Decimal("10.0"),
        amount_out=Decimal("9.9995"),
        time_delta_seconds=300,
        block_delta=1,
    )

    assert confidence == ConfidenceLevel.L2_HIGH_CONFIDENCE

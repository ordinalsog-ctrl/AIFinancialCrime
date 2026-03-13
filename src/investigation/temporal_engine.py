"""
AIFinancialCrime — Temporal Pattern Engine
==========================================
Analyses the timing of Bitcoin transactions for forensic intelligence.

Detections:
  1. Business Hours Pattern     — txs cluster within 09:00–18:00 UTC±N
  2. Night/Weekend Activity     — suggests automated bots or non-EU actors
  3. Rapid Succession           — hops within minutes (pre-planned, scripted)
  4. Time-Delayed Hops          — deliberate waiting to beat 24h monitoring windows
  5. Timezone Inference         — statistical peak-hour analysis → likely TZ
  6. Velocity Pattern           — sudden acceleration/deceleration of hop frequency
  7. Temporal Clustering        — hops that cluster around regulatory-aware times

Output feeds into:
  - Confidence level adjustment (rapid succession → L2, delayed → L3/L4)
  - Report "Temporal Analysis" section
  - Serial Actor profile (behavioural fingerprint)
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from src.core.logging_config import get_logger

logger = get_logger("aifc.temporal")


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class TemporalHop:
    """Minimal hop data needed for temporal analysis."""
    txid: str
    timestamp: int          # Unix epoch (UTC)
    amount_btc: float
    hop_index: int

    @property
    def dt(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)

    @property
    def hour_utc(self) -> int:
        return self.dt.hour

    @property
    def weekday(self) -> int:
        return self.dt.weekday()   # 0=Mon … 6=Sun

    @property
    def is_weekend(self) -> bool:
        return self.weekday >= 5


@dataclass
class TimezoneEstimate:
    utc_offset_hours: int       # e.g. +1 = CET, -5 = EST
    confidence: float           # 0.0 – 1.0
    region: str                 # "Europe/Central", "Europe/Eastern", "US/Eastern", etc.
    peak_local_hour: int        # Most active local hour
    evidence: str


@dataclass
class TemporalPattern:
    pattern: str               # identifier
    severity: str              # "info" | "low" | "medium" | "high"
    description: str
    affected_txids: list[str]
    confidence_delta: float    # adjustment to base confidence (-0.2 to +0.2)
    metadata: dict = field(default_factory=dict)


@dataclass
class TemporalAnalysisResult:
    hops: list[TemporalHop]
    patterns: list[TemporalPattern]
    timezone_estimate: Optional[TimezoneEstimate]
    total_duration_hours: float
    avg_hop_interval_minutes: float
    min_hop_interval_seconds: float
    max_hop_interval_seconds: float
    business_hours_ratio: float    # fraction of txs during 09–18 UTC
    weekend_ratio: float
    confidence_adjustment: float   # net adjustment from all patterns
    summary: str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known exchange/service operating hours bias
BUSINESS_HOURS_START = 8    # UTC
BUSINESS_HOURS_END = 18     # UTC

# Time deltas for hop classification
RAPID_THRESHOLD_SECONDS = 600        # < 10 minutes = rapid (pre-scripted)
SUSPICIOUS_DELAY_HOURS = 24          # > 24h gap = deliberate delay
REGULATORY_WINDOW_HOURS = 24         # FATF monitoring window (common knowledge)

# Timezone offset → region mapping
TZ_REGIONS = {
    -8: "US/Pacific",
    -7: "US/Mountain",
    -6: "US/Central",
    -5: "US/Eastern",
    0:  "Europe/Western (UK/Portugal)",
    1:  "Europe/Central (DE/FR/NL/PL)",
    2:  "Europe/Eastern (UA/EE/TR)",
    3:  "Europe/Moscow / Middle East",
    4:  "Gulf / UAE",
    5:  "Pakistan",
    6:  "Central Asia",
    7:  "Southeast Asia (TH/VN/ID)",
    8:  "East Asia (CN/HK/SG/TW)",
    9:  "Japan/Korea",
    10: "Australia/Eastern",
}


# ---------------------------------------------------------------------------
# Temporal Pattern Engine
# ---------------------------------------------------------------------------

class TemporalPatternEngine:
    """
    Analyses transaction timing patterns for forensic intelligence.

    Usage:
        engine = TemporalPatternEngine()
        hops = [TemporalHop(txid=..., timestamp=..., amount_btc=..., hop_index=i)
                for i, hop in enumerate(chain)]
        result = engine.analyse(hops)
    """

    def analyse(self, hops: list[TemporalHop]) -> TemporalAnalysisResult:
        if not hops:
            return self._empty_result()

        sorted_hops = sorted(hops, key=lambda h: h.timestamp)
        intervals = self._compute_intervals(sorted_hops)
        patterns = []

        # Run detectors
        patterns.extend(self._detect_rapid_succession(sorted_hops, intervals))
        patterns.extend(self._detect_deliberate_delay(sorted_hops, intervals))
        patterns.extend(self._detect_business_hours_clustering(sorted_hops))
        patterns.extend(self._detect_velocity_change(sorted_hops, intervals))
        patterns.extend(self._detect_regulatory_window_avoidance(sorted_hops, intervals))

        # Timezone inference
        tz_est = self._infer_timezone(sorted_hops)

        # Compute aggregates
        total_duration_h = (
            (sorted_hops[-1].timestamp - sorted_hops[0].timestamp) / 3600
            if len(sorted_hops) > 1 else 0
        )
        avg_interval_min = (
            sum(intervals) / len(intervals) / 60 if intervals else 0
        )
        min_interval_s = min(intervals) if intervals else 0
        max_interval_s = max(intervals) if intervals else 0

        biz_count = sum(1 for h in sorted_hops
                        if BUSINESS_HOURS_START <= h.hour_utc < BUSINESS_HOURS_END)
        biz_ratio = biz_count / len(sorted_hops)
        wknd_count = sum(1 for h in sorted_hops if h.is_weekend)
        wknd_ratio = wknd_count / len(sorted_hops)

        net_confidence = sum(p.confidence_delta for p in patterns)
        net_confidence = max(-0.4, min(0.4, net_confidence))

        summary = self._build_summary(
            sorted_hops, patterns, tz_est, total_duration_h,
            avg_interval_min, biz_ratio, wknd_ratio,
        )

        logger.info(
            "temporal_analysis_complete",
            hops=len(sorted_hops),
            patterns=len(patterns),
            tz=tz_est.region if tz_est else "unknown",
            duration_h=round(total_duration_h, 1),
            net_confidence_delta=round(net_confidence, 2),
        )

        return TemporalAnalysisResult(
            hops=sorted_hops,
            patterns=patterns,
            timezone_estimate=tz_est,
            total_duration_hours=total_duration_h,
            avg_hop_interval_minutes=avg_interval_min,
            min_hop_interval_seconds=min_interval_s,
            max_hop_interval_seconds=max_interval_s,
            business_hours_ratio=biz_ratio,
            weekend_ratio=wknd_ratio,
            confidence_adjustment=net_confidence,
            summary=summary,
        )

    # -----------------------------------------------------------------------
    # Detectors
    # -----------------------------------------------------------------------

    def _compute_intervals(self, sorted_hops: list[TemporalHop]) -> list[float]:
        return [
            sorted_hops[i + 1].timestamp - sorted_hops[i].timestamp
            for i in range(len(sorted_hops) - 1)
        ]

    def _detect_rapid_succession(
        self, hops: list[TemporalHop], intervals: list[float]
    ) -> list[TemporalPattern]:
        if not intervals:
            return []
        rapid = [(i, iv) for i, iv in enumerate(intervals)
                 if iv < RAPID_THRESHOLD_SECONDS]
        if not rapid:
            return []

        affected_txids = []
        for i, _ in rapid:
            affected_txids.extend([hops[i].txid, hops[i + 1].txid])

        min_iv = min(iv for _, iv in rapid)
        return [TemporalPattern(
            pattern="rapid_succession",
            severity="high",
            description=(
                f"{len(rapid)} Hop(s) in schneller Folge (< {RAPID_THRESHOLD_SECONDS // 60} Min.). "
                f"Kürzestes Intervall: {min_iv:.0f}s. Deutet auf automatisiertes/scripted Vorgehen hin."
            ),
            affected_txids=list(set(affected_txids)),
            confidence_delta=+0.10,   # rapid = more traceable = slightly higher confidence
            metadata={"min_interval_s": min_iv, "rapid_hop_count": len(rapid)},
        )]

    def _detect_deliberate_delay(
        self, hops: list[TemporalHop], intervals: list[float]
    ) -> list[TemporalPattern]:
        if not intervals:
            return []
        delayed = [(i, iv) for i, iv in enumerate(intervals)
                   if iv > SUSPICIOUS_DELAY_HOURS * 3600]
        if not delayed:
            return []

        patterns = []
        for i, iv in delayed:
            hours = iv / 3600
            patterns.append(TemporalPattern(
                pattern="deliberate_delay",
                severity="medium",
                description=(
                    f"Deliberate Pause von {hours:.1f}h zwischen Hop {i} und {i+1} "
                    f"({hops[i].txid[:10]}… → {hops[i+1].txid[:10]}…). "
                    f"Möglicherweise absichtliches Warten zur Umgehung von 24h-Monitoring."
                ),
                affected_txids=[hops[i].txid, hops[i + 1].txid],
                confidence_delta=-0.05,   # longer gap = harder to prove direct intent
                metadata={"delay_hours": round(hours, 1)},
            ))
        return patterns

    def _detect_business_hours_clustering(
        self, hops: list[TemporalHop]
    ) -> list[TemporalPattern]:
        if len(hops) < 4:
            return []
        biz = sum(1 for h in hops
                  if BUSINESS_HOURS_START <= h.hour_utc < BUSINESS_HOURS_END
                  and not h.is_weekend)
        ratio = biz / len(hops)

        if ratio > 0.75:
            return [TemporalPattern(
                pattern="business_hours_clustering",
                severity="info",
                description=(
                    f"{ratio:.0%} der Transaktionen während Geschäftszeiten (Mo–Fr, "
                    f"{BUSINESS_HOURS_START}:00–{BUSINESS_HOURS_END}:00 UTC). "
                    f"Deutet auf manuelles Handeln oder EU/US-nahen Täter hin."
                ),
                affected_txids=[h.txid for h in hops],
                confidence_delta=+0.05,
                metadata={"business_hours_ratio": round(ratio, 2)},
            )]
        elif ratio < 0.20 and len(hops) >= 5:
            night_hops = [h for h in hops
                          if h.hour_utc < 6 or h.hour_utc >= 22]
            return [TemporalPattern(
                pattern="night_activity",
                severity="low",
                description=(
                    f"Überwiegend nächtliche Aktivität ({ratio:.0%} Geschäftszeiten). "
                    f"{len(night_hops)} TX(s) zwischen 22:00–06:00 UTC. "
                    f"Deutet auf Botbetrieb oder asiatische/osteuropäische Zeitzone."
                ),
                affected_txids=[h.txid for h in night_hops],
                confidence_delta=0.0,
                metadata={"business_hours_ratio": round(ratio, 2)},
            )]
        return []

    def _detect_velocity_change(
        self, hops: list[TemporalHop], intervals: list[float]
    ) -> list[TemporalPattern]:
        if len(intervals) < 4:
            return []

        # Compare first half vs second half average interval
        mid = len(intervals) // 2
        avg_first = sum(intervals[:mid]) / mid
        avg_second = sum(intervals[mid:]) / (len(intervals) - mid)

        if avg_first == 0 or avg_second == 0:
            return []

        ratio = avg_second / avg_first
        patterns = []

        if ratio < 0.2:
            patterns.append(TemporalPattern(
                pattern="acceleration",
                severity="medium",
                description=(
                    f"Starke Beschleunigung der Hop-Frequenz in der zweiten Hälfte der Kette "
                    f"(∅-Intervall: {avg_first/60:.1f}min → {avg_second/60:.1f}min). "
                    f"Möglicherweise automatisierte Weiterleitung nach manuellem Start."
                ),
                affected_txids=[h.txid for h in hops[mid:]],
                confidence_delta=+0.05,
                metadata={"ratio": round(ratio, 2)},
            ))
        elif ratio > 5.0:
            patterns.append(TemporalPattern(
                pattern="deceleration",
                severity="low",
                description=(
                    f"Starke Verlangsamung der Hop-Frequenz in der zweiten Kettenhälfte "
                    f"(∅-Intervall: {avg_first/60:.1f}min → {avg_second/3600:.1f}h). "
                    f"Könnte manuelles Eingreifen oder Warteperiode anzeigen."
                ),
                affected_txids=[h.txid for h in hops[mid:]],
                confidence_delta=-0.05,
                metadata={"ratio": round(ratio, 2)},
            ))
        return patterns

    def _detect_regulatory_window_avoidance(
        self, hops: list[TemporalHop], intervals: list[float]
    ) -> list[TemporalPattern]:
        """
        Detects if hops consistently land just after the 24h mark —
        a known pattern to avoid FATF travel-rule monitoring windows.
        """
        if not intervals:
            return []
        just_over_24h = [iv for iv in intervals
                         if 24 * 3600 < iv < 28 * 3600]
        if len(just_over_24h) >= 2:
            return [TemporalPattern(
                pattern="regulatory_window_avoidance",
                severity="high",
                description=(
                    f"{len(just_over_24h)} Hop-Interval(e) liegen gezielt knapp über 24h "
                    f"(Ø {sum(just_over_24h)/len(just_over_24h)/3600:.1f}h). "
                    f"Muster deutet auf deliberate Umgehung von 24h-FATF-Monitoring-Fenstern."
                ),
                affected_txids=[hops[i].txid
                                for i, iv in enumerate(intervals)
                                if 24 * 3600 < iv < 28 * 3600],
                confidence_delta=-0.10,   # bad actor sophistication reduces traceability
                metadata={"count": len(just_over_24h)},
            )]
        return []

    # -----------------------------------------------------------------------
    # Timezone Inference
    # -----------------------------------------------------------------------

    def _infer_timezone(self, hops: list[TemporalHop]) -> Optional[TimezoneEstimate]:
        if len(hops) < 5:
            return None

        # Count activity by UTC hour
        hour_counts = Counter(h.hour_utc for h in hops if not h.is_weekend)
        if not hour_counts:
            return None

        peak_utc_hour = hour_counts.most_common(1)[0][0]

        # Assume "peak local hour" is 14:00 (mid-afternoon = peak activity)
        assumed_local_peak = 14
        utc_offset = assumed_local_peak - peak_utc_hour

        # Normalize to reasonable timezone range [-12, +14]
        while utc_offset > 14:
            utc_offset -= 24
        while utc_offset < -12:
            utc_offset += 24

        # Find closest known timezone
        closest_tz = min(TZ_REGIONS.keys(), key=lambda tz: abs(tz - utc_offset))
        region = TZ_REGIONS.get(closest_tz, f"UTC{utc_offset:+d}")

        # Confidence based on how many hops we have and consistency
        total = sum(hour_counts.values())
        peak_count = hour_counts[peak_utc_hour]
        concentration = peak_count / total
        confidence = min(0.8, 0.3 + concentration * 2)

        return TimezoneEstimate(
            utc_offset_hours=closest_tz,
            confidence=round(confidence, 2),
            region=region,
            peak_local_hour=assumed_local_peak,
            evidence=(
                f"Peak-Aktivität bei {peak_utc_hour}:00 UTC "
                f"({peak_count}/{total} Transaktionen = {concentration:.0%})"
            ),
        )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _build_summary(
        self,
        hops, patterns, tz_est,
        duration_h, avg_interval_min,
        biz_ratio, wknd_ratio,
    ) -> str:
        lines = [
            f"Temporal-Analyse: {len(hops)} Hops über {duration_h:.1f}h "
            f"(∅ {avg_interval_min:.1f} Min./Hop)."
        ]
        if tz_est and tz_est.confidence >= 0.4:
            lines.append(
                f"Geschätzte Täter-Zeitzone: {tz_est.region} "
                f"(UTC{tz_est.utc_offset_hours:+d}, Konfidenz {tz_est.confidence:.0%})."
            )
        for p in patterns:
            if p.severity in ("high", "medium"):
                lines.append(f"⚠ {p.description}")
        return " ".join(lines)

    def _empty_result(self) -> TemporalAnalysisResult:
        return TemporalAnalysisResult(
            hops=[], patterns=[], timezone_estimate=None,
            total_duration_hours=0, avg_hop_interval_minutes=0,
            min_hop_interval_seconds=0, max_hop_interval_seconds=0,
            business_hours_ratio=0, weekend_ratio=0,
            confidence_adjustment=0, summary="Keine Zeitstempeldaten verfügbar.",
        )


# ---------------------------------------------------------------------------
# Convenience: convert pipeline HopChain to TemporalHop list
# ---------------------------------------------------------------------------

def hops_from_chain(hop_chain: list) -> list[TemporalHop]:
    """Convert pipeline HopResult list to TemporalHop list."""
    result = []
    for i, hop in enumerate(hop_chain):
        ts = getattr(hop, "timestamp", 0)
        if not ts:
            continue
        result.append(TemporalHop(
            txid=getattr(hop, "txid", ""),
            timestamp=ts,
            amount_btc=getattr(hop, "amount_btc", 0.0),
            hop_index=i,
        ))
    return result

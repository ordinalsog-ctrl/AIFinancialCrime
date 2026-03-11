from __future__ import annotations

from typing import Any

from afci.intel.patterns import aggregate_pattern_signals, evaluate_pattern_matches


def _rows_as_dicts(cur) -> list[dict[str, Any]]:
    columns = [desc[0] for desc in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def query_k_hop_exposure(conn, seed_address: str, max_hops: int = 3, limit: int = 100) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH RECURSIVE edges AS (
              SELECT DISTINCT i.address AS src, o.address AS dst
              FROM tx_inputs i
              JOIN tx_outputs o ON o.txid = i.txid
              WHERE i.address IS NOT NULL
                AND o.address IS NOT NULL
                AND i.address <> o.address
            ),
            walk AS (
              SELECT %s::text AS address, 0::int AS hop, ARRAY[%s::text] AS path
              UNION ALL
              SELECT e.dst, w.hop + 1, w.path || e.dst
              FROM walk w
              JOIN edges e ON e.src = w.address
              WHERE w.hop < %s
                AND NOT (e.dst = ANY(w.path))
            ),
            ranked AS (
              SELECT address, MIN(hop) AS min_hop, COUNT(*) AS path_count
              FROM walk
              GROUP BY address
            )
            SELECT address, min_hop, path_count
            FROM ranked
            WHERE min_hop > 0
            ORDER BY min_hop ASC, path_count DESC, address ASC
            LIMIT %s
            """,
            (seed_address, seed_address, max_hops, limit),
        )
        return _rows_as_dicts(cur)


def query_entity_exposure(conn, seed_address: str, max_hops: int = 3, limit: int = 50) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH RECURSIVE edges AS (
              SELECT DISTINCT i.address AS src, o.address AS dst
              FROM tx_inputs i
              JOIN tx_outputs o ON o.txid = i.txid
              WHERE i.address IS NOT NULL
                AND o.address IS NOT NULL
                AND i.address <> o.address
            ),
            walk AS (
              SELECT %s::text AS address, 0::int AS hop, ARRAY[%s::text] AS path
              UNION ALL
              SELECT e.dst, w.hop + 1, w.path || e.dst
              FROM walk w
              JOIN edges e ON e.src = w.address
              WHERE w.hop < %s
                AND NOT (e.dst = ANY(w.path))
            ),
            reachable AS (
              SELECT address, MIN(hop) AS min_hop
              FROM walk
              GROUP BY address
            )
            SELECT
              e.entity_id,
              e.name,
              e.category,
              MIN(r.min_hop) AS min_hop,
              ROUND(MAX(ael.confidence)::numeric, 3) AS max_link_confidence,
              ROUND(SUM(ael.confidence / (r.min_hop + 1.0))::numeric, 3) AS weighted_exposure
            FROM reachable r
            JOIN address_entity_links ael ON ael.address = r.address
            JOIN entities e ON e.entity_id = ael.entity_id
            WHERE r.min_hop > 0
            GROUP BY e.entity_id, e.name, e.category
            ORDER BY weighted_exposure DESC, min_hop ASC, e.name ASC
            LIMIT %s
            """,
            (seed_address, seed_address, max_hops, limit),
        )
        return _rows_as_dicts(cur)


def query_pattern_feature_rows(conn, seed_address: str, max_hops: int = 3, limit: int = 200) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH RECURSIVE edges AS (
              SELECT DISTINCT i.address AS src, o.address AS dst
              FROM tx_inputs i
              JOIN tx_outputs o ON o.txid = i.txid
              WHERE i.address IS NOT NULL
                AND o.address IS NOT NULL
                AND i.address <> o.address
            ),
            walk AS (
              SELECT %s::text AS address, 0::int AS hop, ARRAY[%s::text] AS path
              UNION ALL
              SELECT e.dst, w.hop + 1, w.path || e.dst
              FROM walk w
              JOIN edges e ON e.src = w.address
              WHERE w.hop < %s
                AND NOT (e.dst = ANY(w.path))
            ),
            reachable AS (
              SELECT address, MIN(hop) AS min_hop
              FROM walk
              GROUP BY address
            ),
            input_stats AS (
              SELECT
                txid,
                COUNT(*)::int AS vin_count,
                COUNT(DISTINCT address) FILTER (WHERE address IS NOT NULL)::int AS input_addr_count
              FROM tx_inputs
              GROUP BY txid
            ),
            output_stats AS (
              SELECT
                txid,
                COUNT(*)::int AS vout_count,
                COUNT(DISTINCT address) FILTER (WHERE address IS NOT NULL)::int AS output_addr_count,
                COALESCE(SUM(amount_sats), 0)::bigint AS total_output_sats,
                COALESCE(MAX(amount_sats), 0)::bigint AS max_output_sats
              FROM tx_outputs
              GROUP BY txid
            ),
            tx_stats AS (
              SELECT
                t.txid,
                COALESCE(i.input_addr_count, 0) AS input_addr_count,
                COALESCE(o.output_addr_count, 0) AS output_addr_count,
                COALESCE(i.vin_count, 0) AS vin_count,
                COALESCE(o.vout_count, 0) AS vout_count,
                COALESCE(o.total_output_sats, 0) AS total_output_sats,
                COALESCE(o.max_output_sats, 0) AS max_output_sats
              FROM transactions t
              LEFT JOIN input_stats i ON i.txid = t.txid
              LEFT JOIN output_stats o ON o.txid = t.txid
            ),
            tx_reachable AS (
              SELECT DISTINCT
                t.txid,
                MIN(r.min_hop) AS min_hop,
                s.input_addr_count,
                s.output_addr_count,
                s.vin_count,
                s.vout_count,
                s.total_output_sats,
                s.max_output_sats
              FROM transactions t
              JOIN tx_inputs i ON i.txid = t.txid
              JOIN reachable r ON r.address = i.address
              JOIN tx_stats s ON s.txid = t.txid
              WHERE r.min_hop > 0
              GROUP BY t.txid, s.input_addr_count, s.output_addr_count, s.vin_count, s.vout_count, s.total_output_sats, s.max_output_sats
            )
            SELECT
              txid,
              min_hop,
              input_addr_count,
              output_addr_count,
              vin_count,
              vout_count,
              total_output_sats,
              CASE
                WHEN total_output_sats = 0 THEN 0::numeric
                ELSE (max_output_sats::numeric / total_output_sats::numeric)
              END AS top_output_ratio
            FROM tx_reachable
            ORDER BY min_hop ASC, txid ASC
            LIMIT %s
            """,
            (seed_address, seed_address, max_hops, limit),
        )
        return _rows_as_dicts(cur)


def query_pattern_signals(conn, seed_address: str, max_hops: int = 3, limit: int = 50) -> list[dict[str, Any]]:
    feature_rows = query_pattern_feature_rows(conn, seed_address=seed_address, max_hops=max_hops, limit=max(200, limit * 8))
    matches = evaluate_pattern_matches(feature_rows)
    return aggregate_pattern_signals(matches, total_tx=len(feature_rows))[:limit]


def query_pattern_matches(conn, seed_address: str, max_hops: int = 3, limit: int = 100) -> list[dict[str, Any]]:
    feature_rows = query_pattern_feature_rows(conn, seed_address=seed_address, max_hops=max_hops, limit=max(200, limit * 2))
    matches = evaluate_pattern_matches(feature_rows)
    ordered = sorted(matches, key=lambda m: (m.min_hop, -m.confidence, m.pattern_name, m.txid))

    out: list[dict[str, Any]] = []
    for m in ordered[:limit]:
        out.append(
            {
                "txid": m.txid,
                "min_hop": m.min_hop,
                "pattern_name": m.pattern_name,
                "rule_id": m.rule_id,
                "reason_code": m.reason_code,
                "confidence": m.confidence,
                "severity_weight": m.severity_weight,
                "feature_values": m.feature_values,
                "threshold_values": m.threshold_values,
            }
        )
    return out

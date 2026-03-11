from __future__ import annotations


def project_address_to_tx_edges() -> str:
    """Cypher template for creating graph edges from normalized tx data."""
    return (
        "MATCH (a:Address),(t:Tx) "
        "WHERE a.address = $address AND t.txid = $txid "
        "MERGE (a)-[:SPENT_IN]->(t)"
    )

# AIFinancialCrime - Architecture v0

## Scope
- Bitcoin L1 only
- AML investigation workflow: wallet/deposit investigation
- Deterministic outputs: risk score, flow graph, explainable findings

## Layers
- Ingestion: Bitcoin RPC block/tx fetch and normalization
- Storage: PostgreSQL (facts), Neo4j (graph projection)
- Intelligence: clustering, exposure, risk propagation
- Application: case API, evidence timeline, report export

## Initial Deliverables
1. Postgres schema for blocks/transactions/addresses/labels/cases
2. Parser skeleton to normalize block data
3. Graph projection skeleton
4. Risk engine skeleton with explainability format

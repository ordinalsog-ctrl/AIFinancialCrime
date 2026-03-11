# Risk Methodology (v1.1.0)

## Objectives
- Deterministic and reproducible risk output.
- Explainable drivers with auditable evidence.
- Persisted assessment snapshots for review and model governance.

## Core formula
- `effective_contribution = base_contribution * confidence`
- `score = min(100, sum(effective_contribution))`

## Entity exposure factors
- `severity_weight` from entity category.
- `weighted_exposure` (capped to 1.0).
- `proximity_factor` from graph distance (`min_hop`).
- `confidence` from entity-link confidence.

## Pattern signal factors
- `severity_weight` from rule definition.
- `density` (matched tx / considered tx).
- `proximity_factor` from closest hop.
- `activity_factor` from tx count.
- `confidence` from average rule confidence.

## Governance fields
Every assessment includes:
- `model_name`, `model_version`
- `ruleset_id`, `ruleset_version`
- `finding_rows` with base/effective contribution and metadata

## Persistence
- Summary snapshot: `risk_assessments`
- Per-finding records: `risk_assessment_findings`
- Full JSON payload retained in `payload_json`.

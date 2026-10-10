# Bounded operational limits

Current safeguards include bounded fleet/schedule/compliance evaluation,
history (maximum 500 points), export rows, agent payloads, and request IDs.
These are correctness and abuse limits, not load-test results. Metrics remain
process-local and intentionally avoid endpoint/user identifiers as labels.

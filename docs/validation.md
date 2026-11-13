# Validation evidence

The offline suite contains 27 tests and 40 unique fixture cases from 41 raw records. Run the README commands to reproduce them; the alternate set uses seed 42 and reference time 2025-01-01T00:00:00Z.

Supplied manual Splunk exports were compared against the Python reference: each dataset had 40 unique IDs, complete ID-set equality and all 15 output fields equal. Both diagnostic exports had 40 matching rows. These comparisons corroborate logic parity, not complete provenance. The original default Inspector expired; complete per-run lookup-resolution logs and timestamped before/after server hashes remain pending. No new capture is claimed yet.

Server hashes supplied by the operator matched independently recomputed local inputs, but were not timestamped before/after those searches. Raw vendor parsing, index integration, scheduling, clock-skew controls and production effectiveness are untested.

CI is configured to run unit tests, default/alternate fixture validation and Gitleaks history scans. A configured workflow is not proof of successful execution; inspect its run status for the commit being evaluated.

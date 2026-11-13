# Validation evidence

The offline suite contains 27 tests and 40 unique fixture cases from 41 raw records. Run the README commands to reproduce them; the alternate set uses seed 42 and reference time 2025-01-01T00:00:00Z.

Fresh manual Splunk runs on 2026-11-13 UTC produced default and alternate exports with 40 unique IDs each, complete ID-set equality and all 15 output fields equal to the Python reference. Both diagnostic exports had 40 matching rows. The sanitized appendix retains these output bytes, which also equal the earlier supplied exports. Equality alone does not identify which lookup context was used.

The private capture retains per-run Inspector text, search logs and a REST lookup inventory. Logs explicitly identify each app context and the evaluation CSV path. For baseline, policy and exceptions, logged sizes and modification times uniquely match the intended files in the inventory and operator-supplied stat output. This corroborates binding by inference; the logs do not explicitly give every lookup's full path.

Operator-supplied timestamped snapshots bracket the five fresh jobs over 390 seconds. All 18 lookup hashes, sizes and modification/change timestamp strings agree across the snapshots. These are user-supplied terminal records, not independently observed shell execution or a trusted-clock attestation. One malformed change-time string is identical in both records. Snapshot equality does not prove continuous filesystem immutability.

Full logs retain warnings about implicit CSV filename fallback, disabled KV Store certificate verification and unavailable remote-provider logs. Lookup loads succeeded and no ERROR/FATAL was found in the captured logs; no warning-free or infrastructure-remediation claim is made. Binding is partly inferred; the evidence supports the stated synthetic parity claims, not fully proven lookup resolution. Private logs, identifiers and server paths are excluded from this repository.

Raw vendor parsing, index integration, scheduling, clock-skew controls and production effectiveness are untested. CI is configured to run unit tests, default/alternate fixture validation and Gitleaks history scans. A configured workflow is not proof of successful execution; inspect its run status for the commit being evaluated.

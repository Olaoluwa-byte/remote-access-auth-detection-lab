# Operational limitations

- Lookup write access is trusted. minimum_samples accepts values from 1 upward; default 3 is illustrative, not a security floor.
- Known successful training with not_performed MFA can teach legitimate non-MFA methods. Explicit policy independently controls MFA requirements.
- Unsupported methods are invalid and have zero behavioral flags. Future operational integration must route invalid telemetry for triage; the failed-MFA alert guarantee applies only to schema-valid successes.
- Python rejects duplicate lookup keys automatically; SPL relies on manual integrity preflight. Automate integrity checks before scheduling. Live duplicate controls used exact-content duplicates, not conflicting duplicates.
- Live malformed-field checks covered blank MFA and blank valid only. Other guards have offline coverage or remain untested live.
- Unknown required MFA may alert under break-glass; unsupported MFA never becomes passed.
- Baseline refresh/expiry, raw parsing, ingestion-time/clock guards and scheduled operation remain future work.
- Fresh capture includes per-run logs, inventory and matching operator-supplied before/after snapshots. Lookup binding is corroborated by metadata uniqueness, not explicit paths. See [validation evidence](validation.md) for warnings and provenance limits.

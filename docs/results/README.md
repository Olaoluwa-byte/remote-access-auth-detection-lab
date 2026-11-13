# Supplied synthetic output appendix

These output bytes match the fresh manual runs captured on 2026-11-13 UTC and the earlier supplied exports. See ../validation.md for capture provenance and limitations. The two files are byte-identical because output fields do not carry fixture time or seed-dependent IP values. Their equality alone cannot identify the lookup context. No SID, server path or private transcript is included.

Compare each file by event_id against the corresponding freshly generated actual.json; require 40 unique IDs, exact ID-set equality and equality for every reference field. Default uses the committed fixtures; alternate uses seed 42 / reference 2025-01-01T00:00:00Z. The JSON contains integer values; compare them to CSV strings using str(value). Hashes establish these appendix bytes, not provenance of execution.

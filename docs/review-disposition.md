# Publication preparation dispositions

These are documented design choices for the approved preparation scope, not final user acceptance of the project.

R1/R11: fresh-root candidate omits original private evidence/history, including the local path and empty evidence file. Original private repository is preserved. Do not make the original repository public: its old branches/history still contain private material.
R2/R3: open provenance gaps; fresh logs, lookup inventory and timestamped pre/post server hashes required. No rerun is claimed.
R4: manual duplicate preflight only in SPL; automate before scheduling.
R5: only blank MFA/valid contract controls executed live; additional guard cases untested live.
R6: baseline lookup and minimum_samples are operator-trusted data; accepted values start at 1, default is 3. Protect lookup write access.
R7: known not_performed training allowed; independent policy enforces required MFA.
R8: unsupported methods invalid with zero behavioral flags; schema-valid scope bounds failed-MFA alert guarantee; future integration must separately triage invalid telemetry.
R9: missing/unsupported MFA never passes; unknown required MFA can alert during break-glass.
R10: current summaries replace stale private transcripts; historical evidence preserved separately.
F10/F11: baseline lifecycle, raw parsing, clock/ingestion guards and scheduled operation remain future work.

Candidate needs independent review of changes and public-facing claims, then explicit user acceptance and publication authorization.

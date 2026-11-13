# Manual Splunk validation and provenance recapture

Initial manual fixture runs produced parity-matching exports. Complete provenance recapture remains pending; see validation.md. Use only authorized task-owned contexts. Do not enable schedules or external actions.

1. Use a clean checkout of the exact reviewed repair commit. Record HEAD, Python
   version and SHA-256 hashes. Create new output directories (choose fresh names if
   these exist). Run from repository root:

   ```bash
   python3 -m c07.validate --root . --output build/live-default
   python3 -m c07.generate --output build/live-alt-fixtures --seed 42 --reference-time 2025-01-01T00:00:00Z
   python3 -m c07.validate --root build/live-alt-fixtures --output build/live-alt-results
   ```

   Require exit 0 and 40/40 in BOTH acceptance reports. Validation loads and checks
   all three lookup tables for normalized/unique keys, allowed method values,
   numeric metadata, binary permission flags and valid exception intervals.
2. Use two dedicated task-owned app contexts (choose fresh names when needed) `c07_fix01_default` and `c07_fix01_alternate`,
   plus a separate `c07_fix01_negative` for controls. Keep all lookup permissions
   app-local; do not globally share them or overwrite existing app files. Upload
   default `lookups/c07_*.csv` and the two CSVs in `build/live-default` to the default
   app. Upload alternate lookups from `build/live-alt-fixtures/lookups` and the two
   CSVs from `build/live-alt-results` to the alternate app. Identical filenames are
   intentional ONLY within isolated namespaces. Stop if isolation cannot be assured.
   Record app, filenames, hashes and row counts; restrict modification privileges.
3. Preflight lookup integrity inside EACH app before running detection. Execute
   these separately; every result must contain zero duplicate-key rows:

   ```spl
   | inputlookup c07_baseline.csv
   | stats count by gateway_id user
   | where count!=1
   ```

   ```spl
   | inputlookup c07_policy.csv
   | stats count by gateway_id user
   | where count!=1
   ```

   ```spl
   | inputlookup c07_exceptions.csv
   | stats count by gateway_id user auth_method
   | where count!=1
   ```

   These duplicate checks supplement, not replace, Python validation and byte-hash
   checks: null keys may be omitted by stats. Download/export the uploaded tables,
   verify their bytes against the validated files, and require baseline 7 rows,
   policy 6, exceptions 2. Missing file, changed bytes, null keys, multivalue lookup
   output, metadata error or lookup warning invalidates the entire run. Both Python
   and SPL must use minimum_samples from this exact baseline CSV.
4. Run `detections/c07_auth_deviation.spl` unchanged in the correct app. inputlookup
   consumes fixture CSV, not indexes or the time picker. event_epoch governs all
   time decisions. Capture SID, app context, query text, Job Inspector errors/warnings, search.log and full result CSV immediately. Extend job lifetime before expiry. Capture lookup-table-files REST inventory; require evidence of resolved paths for each lookup, not just matching names. Take timestamped server sha256sum and stat output before and after each dataset run. Preserve transcripts and compare hashes; do not reconstruct missing timestamps retrospectively.
   Expect exactly 40 unique IDs from 41 raw records, with all flags (including
   failed_mfa_on_success), mfa_note, disposition, exception fields, parse_error and
   occurrence count equal to actual.json. Compare every ID and field externally,
   not merely aggregate totals. There must be no missing or extra IDs.
5. Append `detections/compare_expected.spl` as an additional diagnostic. All 40 rows
   must have matched=1; explicitly verify quoted 'case' parses. This comparison
   checks decision flags, note, disposition, exception ID/application and occurrences;
   use the complete external comparison for reason/parse_error and omitted IDs.
   Labels enter only after detection, never as its inputs. Repeat steps 3–5 in the
   alternate app and capture a separate SID, hashes, results and full ID comparison.
6. Negative controls in the third app, using copies only:
   - Blank mfa_result for an otherwise normal required-MFA successful event:
     expect alert, mfa_violation=1, telemetry_unknown=1. Blank the mfa_note too:
     expect contract_missing_note. This tests damaged normalized CSV, not raw parsing.
   - Blank valid for that event: expect invalid; all behavioral flags zero.
   - Duplicate an existing baseline key: preflight must produce a duplicate row
     and the run must be rejected before detection, regardless of SPL's own behavior.
     Repeat for policy and exception keys. Never accept arbitrary first-match output.
   - Set minimum_samples=4 for the three-sample alice/gw-east history in BOTH the
     local control CSV and uploaded copy: Python and SPL must show baseline_unknown=1.
   Restore only task-owned control copies. Record each mutation, expected/actual
   result and SID. These controls produced the expected supplied exports in the initial run; full resolution provenance is still incomplete.
7. Preserve every failure and warning tied to exact commit, app and lookup hashes.
   If parity fails, stop and reconcile; Python passing does not prove SPL correctness.
   Cleanup only newly created task-owned contexts/files after agreed retention,
   preserving exported evidence. No operational schedule needs rollback.

Known lab issues remain outside scope: time synchronization, scheduled-search
concurrency skips and existing C05/C09 pipeline issues. Absolute fixture timestamps
avoid relying on the wall clock for this bounded manual test.

Before later indexed-data integration, approve source parser/trust model,
index/sourcetype/time extraction, deduplication windows, baseline refresh/expiry,
clock-skew and ingest-time guards, retention, permissions, scheduling, load test and
rollback. These guards are not implemented by the current lookup-only query.

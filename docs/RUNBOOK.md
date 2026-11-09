# Runbook and review

The automated native demo checks late corrections/old cutoffs, unknown gaps, microsecond/touching bounds, observed-time ties/reordering, idempotency/conflict, rejected data, concurrent writers/identities, seeded overlaps, before/after-commit API kills, restart and bounded original-history pages. Independent SQL snapshots and 1,866 point checks reconstruct 23 committed corrections and four current segments. History-row count is reported per run: the serialized order of overlapping concurrent corrections changes the carried history segments. Local R2 slices observed 49 and 50 rows; neither is a required pass threshold. The independent inventory and point oracle use the actual committed revision order. These bounded observations are not production capacity/performance.

On UNKNOWN retain the operation identity and byte-identical canonical intent. Retry/query that identity; never invent a new ID. On an unavailable read, do not invent a value or a latest revision. Retain incomplete receipts/history rather than retrying until a desired result appears. init refuses an existing schema; no script resets existing data.

For manual local exploration, first prepare fixtures as in README, then launch tools/pg_host.py in a separate Linux/WSL terminal with --fixtures artifacts/services --out artifacts/host. Its fresh generated connection file is private. In the API terminal set REFERENCE_LAB_DB from that owned file, run reference init, then reference serve8123. A client terminal only needs the HTTP URL and examples/*.json. The supervisor is bounded to15minutes and stops its own PostgreSQL instance; restarting this profile requires fresh paths. Do not use owner/production connections.

Investigate native --version, archive manifest/provenance, sanitized host error, retained API/server output, SQL snapshots and independent expected corrections. Never paste the private connection file or whole demo folder into an issue. sourceLabel/observedAt are synthetic attribution metadata, not vendor authenticity.

PostgreSQL constraints are tested by the expected SQLSTATE23P01 for overlap and23514 for invalid ranges. Generic command failure is not accepted as proof of the intended constraint. Checks include both temporal axes and positive revision/half-open bounds; original row-ID gaps do not imply knowledge-revision gaps.

Profile configured bounds:15minutes/256MiB logs,64MiB shared buffers/24PG connections/256MiB max_wal_size; these are settings, not measured total RSS/disk guarantees. API/CLI run natively on each calling OS, PostgreSQL on existing Linux/WSL. Local Linux binaries can be cross-built but are marked local candidates; public packages require native CI.

Review slices: precision/units/input/response validation; committed revision and durable identity; two-dimensional split/carry/provenance; independent history/point oracle; notices/provenance/package delivery. No live account/feed/market/production action is part of the review.

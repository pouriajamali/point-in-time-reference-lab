# v0.1.0-preview.2 - Point-in-Time Instrument Reference Lab

Connection ownership correction: a newly allocated Npgsql connection remains owned by `Store` until opening succeeds. Failure and cancellation await disposal before rethrowing the original exception; cleanup failure cannot replace it. Successful open transfers the live connection to the existing caller. SQL, transaction semantics, pooling, public contracts and dependencies stay unchanged.

Nine ownership regressions include real refused loopback connections and cancelled handshakes, object-reuse disposal checks, awaited cleanup, secondary cleanup failures and successful ownership transfer. The red observation seam preserves the original await-open/return behavior; the same test bytes then pass after cleanup is added. These tests do not measure production leaks or performance.

C# layout is expanded in a separate reviewed delta from the ownership repair. Full-tree syntax, exact token text/values and non-whitespace trivia are preserved. Frozen architecture evidence remains tied to the earlier release; this preview has its own source and native delivery evidence.

Fresh one-instrument Point-in-Time Reference API/CLI: committed local knowledge revisions, native effective/knowledge ranges, two-dimensional exclusion, late correction without lookahead, explicit scaled units/UTC precision, source provenance, bounded original history, durable idempotency and uncertain commit resolution.

History-row counts are reported from each run's actual committed concurrent order, rather than assuming one fixed count of carried segments. The independent SQL inventory and point oracle validate that order; the API, data contract, tests and limits are unchanged by this documentation clarification.

Published packages require native Windows/Linux build/test/package jobs, exact source manifests and actual download verification. Local candidate evidence is distinct. No hosted service, real data authenticity, production capacity or external restore recovery is claimed. Npgsql/Core/ASP.NET runtime graph and original notices are included; raw signed NuGet archive checksums are distinct from canonical lock content identities.

No resume, existing portfolio, private/shared system or trading/account change.

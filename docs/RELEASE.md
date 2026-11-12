# v0.1.0-preview.3 candidate — source units verified, unpublished

The history client now requires an exact complete page of original receipts, beginning at afterRevision+1 and ending at the page-size/head boundary. Ordered but omitted/truncated receipt histories fail closed through the existing UNAVAILABLE path. Full receipt validation, public signatures, SQL, transaction/ownership behavior and one SYNTH instrument are retained; storage row_id gaps remain legal.

Local source runs recorded 51 passing unit cases on each native Windows/Linux environment, retaining the original 39 cases and twelve new validator vectors. Using identical new test bytes against the serviced baseline produced exactly five designated omission failures on each OS. These are source-unit observations. The seven-response packaged-client wire fixture and the separate seventeen-input late-correction/page-boundary scenario with independent full receipt/intent, effective-point and SQL oracles still require passing runtime receipts. Existing ownership/domain cases and the earlier integration matrix remain unchanged.

Selected servicing uses SDK10.0.404 and Core/ASP.NET10.0.15. The four runtime mappings have been reconciled from actual signed archives, normalized identities and original license/notice bytes; the three managed lockfiles are unchanged. Private sealed-local preparation limits only unreferenced framework prefetch with DisableTransitiveFrameworkReferenceDownloads=true; signature and audit-all validation remain enabled. Native packages, the pending wire/database proofs, exact-commit CI and actual downloadable preview.3 assets are not established. Prior preview.2 assets, tags, signatures and verified download links remain unchanged.

## Published baseline: v0.1.0-preview.2 - Point-in-Time Instrument Reference Lab

Connection ownership correction: a newly allocated Npgsql connection remains owned by `Store` until opening succeeds. Failure and cancellation await disposal before rethrowing the original exception; cleanup failure cannot replace it. Successful open transfers the live connection to the existing caller. SQL, transaction semantics, pooling, public contracts and dependencies stay unchanged.

Nine ownership regressions include real refused loopback connections and cancelled handshakes, object-reuse disposal checks, awaited cleanup, secondary cleanup failures and successful ownership transfer. The red observation seam preserves the original await-open/return behavior; the same test bytes then pass after cleanup is added. These tests do not measure production leaks or performance.

C# layout is expanded in a separate reviewed delta from the ownership repair. Full-tree syntax, exact token text/values and non-whitespace trivia are preserved. Frozen architecture evidence remains tied to the earlier release; this preview has its own source and native delivery evidence.

Fresh one-instrument Point-in-Time Reference API/CLI: committed local knowledge revisions, native effective/knowledge ranges, two-dimensional exclusion, late correction without lookahead, explicit scaled units/UTC precision, source provenance, bounded original history, durable idempotency and uncertain commit resolution.

History-row counts are reported from each run's actual committed concurrent order, rather than assuming one fixed count of carried segments. The independent SQL inventory and point oracle validate that order; the API, data contract, tests and limits are unchanged by this documentation clarification.

Published packages require native Windows/Linux build/test/package jobs, exact source manifests and actual download verification. Local candidate evidence is distinct. No hosted service, real data authenticity, production capacity or external restore recovery is claimed. Npgsql/Core/ASP.NET runtime graph and original notices are included; raw signed NuGet archive checksums are distinct from canonical lock content identities.

No resume, existing portfolio, private/shared system or trading/account change.

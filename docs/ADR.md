# Decisions

1. Committed revision instead of an ambiguous wall-clock knownAt. A transaction-start timestamp does not establish commit visibility/publication; observed times can tie or arrive out of order. The revision makes the knowledge convention inspectable and testable.
2. Native PostgreSQL18 range types and a two-dimensional GiST exclusion. A blanket effective-overlap prohibition would reject legitimate corrections. A single instrument avoids an implicit btree_gist extension/equality-key requirement; multiple instruments need a separate schema/privilege decision.
3. Explicit Npgsql10 SQL in one transaction, no competing ORM/migration model. The instrument lock deliberately trades write concurrency for a small auditable correctness boundary.
4. Original receipts plus provenance on carried segments. An independent oracle keeps an ordered list of covering corrections and chooses the last committed one for a point; it does not copy the application's range-splitting algorithm.
5. Stable .NET10 LTS/C#14, strict .NET JSON presence/duplicate/unmapped/null handling, bounded loopback HTTP and source-root configuration. No preview, paid registry, live feed or proprietary instrument model.
6. Actual shipped graph from the native .deps.json. Npgsql and Core/ASP.NET runtime packs ship; resolved abstractions represented by the framework are not falsely listed as separate bundled NuGet libraries. Full original license texts/copyright/notices and raw signed-archive hashes remain distinct from normalized lock identities.

Technical handoff/decision evidence does not claim actual people-management, production finance/HFT operation, data authenticity or exclusive ownership.

## Technology-refresh source decision, 2026-11-14

Delivered preview.3 remains the .NET10 LTS/C#14 baseline described above. The separately prepared preview.4 candidate selects metadata-pinned SDK11.0.100/net11.0/runtime11.0.0 and stable C#15. Official metadata describes .NET11 as STS/GA; this choice alone proves no compatibility, diagnostic quality or speed benefit.

The application, tests, SQL, semantic/wire fixtures, Npgsql10.0.3 and explicit xunit.v3 4.0.3 stay unchanged. No preview language feature, AOT, ReadyToRun, trimming, floating SDK/package selection or weakened warning/audit/signature policy is permitted. The old locks and four runtime notice slots remain unmodified until actual approved SDK11/runtime evidence exists. Project05 target execution requires the admitted shared handoff and its own reviewed resource allocation; this decision is source-preparation authority only.

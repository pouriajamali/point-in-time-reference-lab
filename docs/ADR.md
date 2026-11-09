# Decisions

1. Committed revision instead of an ambiguous wall-clock knownAt. A transaction-start timestamp does not establish commit visibility/publication; observed times can tie or arrive out of order. The revision makes the knowledge convention inspectable and testable.
2. Native PostgreSQL18 range types and a two-dimensional GiST exclusion. A blanket effective-overlap prohibition would reject legitimate corrections. A single instrument avoids an implicit btree_gist extension/equality-key requirement; multiple instruments need a separate schema/privilege decision.
3. Explicit Npgsql10 SQL in one transaction, no competing ORM/migration model. The instrument lock deliberately trades write concurrency for a small auditable correctness boundary.
4. Original receipts plus provenance on carried segments. An independent oracle keeps an ordered list of covering corrections and chooses the last committed one for a point; it does not copy the application's range-splitting algorithm.
5. Stable .NET10 LTS/C#14, strict .NET JSON presence/duplicate/unmapped/null handling, bounded loopback HTTP and source-root configuration. No preview, paid registry, live feed or proprietary instrument model.
6. Actual shipped graph from the native .deps.json. Npgsql and Core/ASP.NET runtime packs ship; resolved abstractions represented by the framework are not falsely listed as separate bundled NuGet libraries. Full original license texts/copyright/notices and raw signed-archive hashes remain distinct from normalized lock identities.

Technical handoff/decision evidence does not claim actual people-management, production finance/HFT operation, data authenticity or exclusive ownership.

# Temporal and wire contract

One synthetic instrument, SYNTH. Its authoritative knowledge cutoff is the committed per-instrument knowledgeRevision, 1..4,096. Bootstrap head 0 is not a queryable known revision. A cutoff above the committed head is rejected rather than treated as latest. observedAt is caller-supplied receipt metadata; it is neither external publication time nor actual commit time. Equal or out-of-order observed times never reorder committed knowledge.

A correction supplies operationId, effectiveFrom/effectiveTo, tickSizeMicros, contractMultiplierMicros, observedAt and sourceLabel. Identity/source labels are 1..64 lowercase ASCII alphanumeric/hyphen characters with an alphanumeric first character. Times accept YYYY-MM-DDTHH:mm:ssZ or exactly six fractional digits followed by Z, normalize to six digits and require UTC/microsecond precision. The effective domain is [2000-01-01,2100-01-01); the exclusive interval upper bound may equal 2100. Empty/reversed intervals, alternate offsets, excess precision, zero/negative/out-of-bound scaled units, duplicate/missing/null/unknown JSON fields and frames above16KiB deny.

Tick and multiplier are integers1..1,000,000,000, scaled by1,000,000. The JSON writer emits 64-bit values as strings. Canonical intent is UTF-8:
reference-v1 + newline + operationId + newline + SYNTH + newline + normalized effectiveFrom + newline + effectiveTo + newline + invariant tick integer + newline + multiplier integer + newline + normalized observedAt + newline + sourceLabel + newline.
Its SHA256, unique operationId and original result receipt survive revision changes/restarts. Same normalized intent replays its original knowledge revision; conflicting reuse rejects without another revision.

Writers serialize on the singleton instrument state row FOR UPDATE. The next revision, immutable receipt, closed/replacement range rows and state counts are one transaction. Abort before commit creates no known revision. Identity-generated storage row IDs may have gaps; they are not the knowledge authority. A lost response after possible commit is UNKNOWN until same-identity retry/history resolves it. No new retry identity is invented.

Storage uses native tstzrange effective intervals and int8range knowledge intervals. Both are half-open; knowledge may have an unbounded upper end for current assertions. The exclusion constraint applies overlap checks in BOTH dimensions. Effective overlap alone is legitimate for corrections across disjoint knowledge intervals; knowledge overlap alone is legitimate for disjoint effective intervals. No btree_gist extension is needed for this one-instrument range-only constraint.

A new interval closes every overlapping current assertion's knowledge range at the new revision, retains the old complete effective interval for earlier cutoffs, and carries any unchanged left/right fragments into new assertions with their original value provenance. New values get their own origin. The current assertion's revision is distinct from the original value's revision/observedAt. Earlier queries cannot see future-origin values.

A query requires effectiveAt + knownThroughRevision and returns KNOWN/NOT_KNOWN plus exact provenance. A client validates the echoed instrument, time/cutoff, receipt intent and origin revision; a successful parse alone is insufficient. History is paged at16 original receipts. It preserves source/observed metadata and original inputs.

Limits: at most4,096 committed corrections/current segments and50,000 total history rows; projected capacity is checked before changes. Body16KiB, header8KiB,16connections/eight request slots, finite connection/statement/request deadlines. Limits are failure policy, not throughput/availability guarantees. API is plaintext on literal loopback and trusted local lab only, not authentication or a production service.

Ordinary process restart retains state. Arbitrary external database rollback/restore, lineage recovery, multiple instruments/sites, real feeds, paid/proprietary data, price reconstruction and financial prediction are outside v1. There is no reset/history-rewrite path to regain availability.

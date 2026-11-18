# v0.1.0-preview.4 - .NET11 maintenance release

SDK11.0.100, net11.0, stable C#15 and Core/ASP.NET11.0.0; Npgsql10.0.3 and
xunit.v3 4.0.3 remain pinned. Application features, schema, temporal semantics,
fixtures and independent acceptance oracles are unchanged. No benchmark claim.

All three SDK-generated locks passed both RID contexts. Eighteen retained managed
version/content identities are unchanged; SDK framework pruning removed the two
Microsoft.Extensions Abstractions10.0.0 entries. Required signature validation,
the already-verified repository signer pins, full original notices and complete
current advisory data remain active. WindowsDesktop is an input, not a shipped
framework; the shipped graph is Npgsql plus Core and ASP.NET runtimes.

Both native archives bind signed source `625b1335aaf76a28fc1e7416c0187d356eaa60d8` and its exact tree.
Each passed 51 units, eight native package checks, seven wire responses and the
eight-test/27-subprocess signature-verifier suite. Linux additionally passed the
original PostgreSQL18.6 14-case/23-correction/1,866-point matrix and the
17-correction/19-row/18-active history/page/replay/conflict scenario.

Windows was tested locally on Windows11 26H2/build26300; the reviewed official
.NET11 OS table omits26H2, so this is observed compatibility. Linux was tested
locally on Ubuntu24.04.5/WSL2 kernel6.18.33.2. No vendor or hosted-CI certification
is inferred. GitHub Actions was not run by owner instruction.

The immutable runtime/source archives retain the README and release-note snapshot
present when source625b133 was built. Those embedded pending-publication statements
are historical; this repository page and the release entry record final delivery.
Healthy Windows tests and its archive were retained byte-for-byte, without replay.


Download and verification instructions: [release](https://github.com/pouriajamali/point-in-time-reference-lab/releases/tag/v0.1.0-preview.4), [README](../README.md) and [PROVENANCE](../PROVENANCE.md). The two native archives, exact Git source ZIP, SHA256SUMS, SSH signature and public key are the six release assets. A co-downloaded key is not an independent trust root.

## v0.1.0-preview.3 — Point-in-Time Instrument Reference Lab

The history client rejects omitted or truncated pages unless they contain exactly min(16, headRevision-afterRevision) original receipts, consecutively from afterRevision+1. Full receipt validation remains active; storage row_id gaps remain legal. This is a synthetic, literal-loopback-only reference API/CLI, with no real feed, trading account or production-service claim.

Runtime and source assets for this release are produced by the native Windows/Linux jobs at signed source 8c844fe917b0d7b1f4389a635bd7950f1cb839b7. The archive manifests, embedded source revision, source ZIP and checksum attestation bind that exact source/tree. A later README/docs commit is a separate documentation head.

Prior local application evidence remains at 90130fe: 51 passing source cases per OS, including twelve literal validator vectors; five designated omission failures against the serviced baseline per OS; eight actual package checks and seven wire responses per OS; Linux original14 cases/23 commits/1866 independent point queries and the separate17-correction/19-row/18-active-segment scenario. The signed bf05702 six-asset private packet retains its original attribution and signatures. It is not reused as the new8c844fe release output.

The exact-tag hosted pipeline independently produces and exercises new native archives, retained PostgreSQL/wire cases, signature-verifier regressions and dependency advisory receipts. Actual hosted run identity and downloadable checksums are recorded in the release evidence after success; local tests alone do not establish them. A clean tag is not a deployment, performance claim or security all-clear.

SDK10.0.404, Core/ASP.NET10.0.15 and Npgsql10.0.3 remain the selected application graph. The shared maintainer actionlint archives and Go/auditor tooling are separate build-time inputs, excluded from the three-component application runtime.

Download the Windows x64 ZIP, Linux x64 tar.gz or exact source ZIP together with SHA256SUMS.txt, SHA256SUMS.txt.sig and SIGNING-PUBLIC-KEY.pub. Verify with a separately trusted verifier and fingerprint SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU, file namespace, principal pouriajamali. The co-downloaded key is not an independent trust root.

Existing preview.1/preview.2 releases, tags, keys and signatures remain immutable. No CV, shared project, paid infrastructure, production deployment or other wave is included.


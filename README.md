# Point-in-Time Instrument Reference Lab

A late instrument correction must update later queries without changing what an earlier as-known query could know. This C#/.NET API and CLI keeps two questions explicit: **when is the value effective?** and **through which committed knowledge revision may the query know corrections?**

Receipt `observedAt` is metadata; it is never silently treated as external publication time or actual database commit time.

Synthetic, literal-loopback-only lab. No real feed, vendor data, historical price reconstruction, orders, account connection, prediction or production service.

**Download:** [Windows/Linux v0.1.0-preview.4](https://github.com/pouriajamali/point-in-time-reference-lab/releases/tag/v0.1.0-preview.4) · **Exact released source:** [`625b133`](https://github.com/pouriajamali/point-in-time-reference-lab/tree/625b1335aaf76a28fc1e7416c0187d356eaa60d8) · [Verify provenance](PROVENANCE.md)

## Try the existing history fixture

A valid JSON page can still omit committed corrections. With `headRevision=17`
and `afterRevision=16`, an empty tail must be rejected; the tail containing
revision17 is complete. This existing fixture exercises that decision in the
actual native CLI with seven owned loopback responses.

Verify the release signature/checksums using [PROVENANCE.md](PROVENANCE.md), then
extract the matching native package. From its root, with Python3.12+ installed:

Linux x64:

```sh
python3 tools/knowledge_boundary.py --wire-only --cli ./reference --out artifacts/quick-wire-history
```

Windows PowerShell:

```powershell
python tools/knowledge_boundary.py --wire-only --cli .\reference.exe --out artifacts/quick-wire-history
```

Expected fields in the printed result and `artifacts/quick-wire-history/receipt.json`
(the complete result also contains the cases, boundary and client OS):

```json
{"status":"PASS","mode":"wire-only","responseCount":7}
```

Five pages missing required revisions are rejected as `UNAVAILABLE`; the complete
first page and final one-revision tail are accepted. Choose a fresh output folder
for each run. This fixture needs no database, installed .NET SDK or POST; it
checks the CLI against owned responses. Use the [full database demo](#run-the-preview)
for the API/PostgreSQL correction and independent SQL/history oracles.

## Maintenance and evidence

The current preview is a .NET11/C#15 maintenance release with unchanged features,
schema, temporal semantics and performance claims. [The maintenance record](docs/MAINTENANCE-HISTORY.md)
keeps the exact runtime/dependency pins, Windows support limitation, Linux/WSL
scope, local acceptance counts, historical CI attribution and immutable archive
snapshot explanation. No hosted CI or vendor certification is inferred for
preview.4; Actions was not run by owner instruction. [Notices](NOTICE.md) and
[provenance](PROVENANCE.md) remain part of the delivery.

## Decision and proof first

| Decision | Executable evidence |
| --- | --- |
| Knowledge follows committed revision, including equal observed times | Concurrent corrections receive unique serialized revisions; independent last-covering-correction oracle |
| Late information must not leak into old queries | Query the same effective instant at revision 1 and revision 2 after a correction |
| Correct both temporal dimensions | Actual PostgreSQL tstzrange + int8range exclusion; overlapping effective history is allowed across disjoint knowledge ranges |
| Preserve source and original corrections | Durable identity/digest/result, immutable receipt history and carried-value provenance |
| Uncertain commit is not a new correction | Kill an owned API before/after commit, then resolve with the same identity |
| A parsed response may still be wrong | Client validates returned intent, instrument, effective time, cutoff and origin revision |

## Connection ownership correction

This version closes a newly allocated connection if opening fails or is cancelled. [Read the ownership decision, executable counterexamples and evidence limits](docs/CONNECTION-OWNERSHIP.md).

## Run the preview

Preview version: [`v0.1.0-preview.4`](https://github.com/pouriajamali/point-in-time-reference-lab/releases/tag/v0.1.0-preview.4). Download **[Windows x64](https://github.com/pouriajamali/point-in-time-reference-lab/releases/download/v0.1.0-preview.4/point-in-time-reference-lab-v0.1.0-preview.4-win-x64.zip)**, **[Linux x64](https://github.com/pouriajamali/point-in-time-reference-lab/releases/download/v0.1.0-preview.4/point-in-time-reference-lab-v0.1.0-preview.4-linux-x64.tar.gz)** or [source](https://github.com/pouriajamali/point-in-time-reference-lab/releases/download/v0.1.0-preview.4/point-in-time-reference-lab-v0.1.0-preview.4-source.zip). Get the [checksums](https://github.com/pouriajamali/point-in-time-reference-lab/releases/download/v0.1.0-preview.4/SHA256SUMS.txt), [checksum signature](https://github.com/pouriajamali/point-in-time-reference-lab/releases/download/v0.1.0-preview.4/SHA256SUMS.txt.sig) and [public key](https://github.com/pouriajamali/point-in-time-reference-lab/releases/download/v0.1.0-preview.4/SIGNING-PUBLIC-KEY.pub); verify downloaded bytes with [PROVENANCE.md](PROVENANCE.md) before execution. The self-contained bundles require no installed .NET SDK. This release uses direct signed local delivery; Actions was not run.

Windows PowerShell, from the extracted package:

```powershell
.\reference.exe --help
python tools/fetch_services.py --out artifacts/upstream
if ($LASTEXITCODE -ne 0) { throw 'Fixture fetch failed' }
$linuxHere = (wsl -d Ubuntu-24.04 -- wslpath -a (Get-Location).Path).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Existing Ubuntu WSL required' }
wsl -d Ubuntu-24.04 -- python3 "$linuxHere/tools/prepare_linux.py" --archives "$linuxHere/artifacts/upstream" --out "$linuxHere/artifacts/services"
if ($LASTEXITCODE -ne 0) { throw 'Fixture preparation failed' }
python tools/integration.py --cli reference.exe --fixtures artifacts/services --out artifacts/demo
if ($LASTEXITCODE -ne 0) { throw 'Demo failed; retain its evidence' }
Get-Content artifacts/demo/receipt.json
```

Native Linux x64:

```sh
python3 tools/fetch_services.py --out artifacts/upstream &&
python3 tools/prepare_linux.py --archives artifacts/upstream --out artifacts/services &&
python3 tools/integration.py --cli ./reference --fixtures artifacts/services --out artifacts/demo &&
cat artifacts/demo/receipt.json
```

The self-contained API/CLI needs no installed SDK. The full demo needs Python 3.12+, existing Ubuntu24.04 x64 (Windows uses an existing Ubuntu-24.04 WSL distribution) and five separately fetched checksum-pinned PostgreSQL/support archives. Helpers only extract archives and own fresh processes/data; no package/system-service/OS-feature installation, cloud, paid account or extension is required. In particular, this single-instrument shape does not install btree_gist.

The automated demo launches the API/CLI natively on the calling OS and PostgreSQL in existing Linux/WSL. It checks fourteen cases with an independent SQL/history oracle, including 23 committed corrections and 1,866 point checks. This is correctness evidence, not a Windows/Linux speed comparison.

Keep the whole demo folder private: `connection.private.json` contains a fresh temporary lab password. The supervisor stops only its owned processes; scratch/logs remain for review. Use new output paths rather than overwriting evidence.

## Understand one correction

With an owned lab database/API running (see [runbook](docs/RUNBOOK.md)), the client itself needs no database password:

```powershell
.\reference.exe ingest http://127.0.0.1:8123 examples/first.json
.\reference.exe ingest http://127.0.0.1:8123 examples/late-correction.json
.\reference.exe query http://127.0.0.1:8123 2024-01-15T00:00:00Z 1
.\reference.exe query http://127.0.0.1:8123 2024-01-15T00:00:00Z 2
```

The first query retains the old `tickSizeMicros=10000`; the second sees `5000`. Both receipt inputs deliberately have the same observed time. A missing or future committed knowledge cutoff is rejected. No implicit latest/wall-clock-only query hides that decision.

Amounts are exact positive integer millionths: tick size in synthetic quote units, multiplier in synthetic quantity per contract. For example, 10,000 tick-size micros means 0.01 synthetic quote unit; 1,000,000 multiplier micros means a factor of 1. No floating-point value is admitted. Instants are UTC Z at whole-second or exactly six-digit microsecond precision, normalized to six digits. Effective intervals are half-open.

```mermaid
flowchart LR
  C[Native CLI / bounded HTTP input] --> A[Literal-loopback API]
  A --> R[One serialized instrument revision]
  R --> H[Receipt / original correction identity]
  R --> S[Effective and knowledge range history]
  Q[effectiveAt + knownThroughRevision] --> A
  O[Independent last-covering-correction oracle] --> S
```

## Build

Current preview.4 source: exact SDK11.0.100 / .NET11.0.0 / C#15 / Npgsql10.0.3. Use the SDK-generated locks with ordinary signature validation and audit-all enabled. Preview.3 historically used SDK10.0.404 / .NET10.0.15 / C#14:

```sh
dotnet restore PointInTimeReference.slnx --locked-mode
dotnet build PointInTimeReference.slnx -c Release --no-restore -m:1
dotnet run --project tests/Reference.Tests -c Release --no-build -- -result-xml artifacts/unit.xml
```

Historical .NET10 private preparation from the sealed local package source added `-p:DisableTransitiveFrameworkReferenceDownloads=true` to avoid prefetching framework families that no project directly references. Required Core/ASP.NET .15 packs, default signature validation and audit-all remain enabled. Hosted CI uses its ordinary online restore route.

See [temporal contract](docs/CONTRACT.md), [decisions](docs/ADR.md), [runbook](docs/RUNBOOK.md), [notices](NOTICE.md) and [provenance](PROVENANCE.md). Native local execution, local cross-builds, public CI and actual public downloads are separate evidence. Original code is MIT; private/shared assets and career materials remain outside scope.

[CI resource policy](docs/CI-POLICY.md): documentation-only changes get real lightweight document/pipeline checks; source, tag and manual runs retain native validation. Release runtime/source assets stay pinned to their exact tag; a later documentation commit does not change or relabel them.

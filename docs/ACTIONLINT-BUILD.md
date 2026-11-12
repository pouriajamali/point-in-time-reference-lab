# Maintainer actionlint — admitted shared input, local consumer verification

This is build-time tooling. Project04 is the sole shared actionlint producer;
project06 supplies its admitted compiler/auditor inputs. Project05 consumes the
identity-bound shared artifacts and tests its own guarded invocation. It does
not repeat their bootstrap, builds or source/binary audits. Public delivery is
a separate gate.

The source-held reference is `tools/actionlint-build.lock.json`. The immutable
shared handoff is SHA256
`23eea97f65bfab85ac0bfd80ffd4038fe5baf3713691f2b2b0fae63f0a9a8cc1`;
its producer lock is
`74c99615e374f683934fd5165a8e62dfa667e54c5b49e195ffc9b88610a4087b`.
Only project identity and the retained one-CPU consumer limit differ. Guard
logic and all fifty negative vectors match the immutable shared source, with
line endings normalized. Original notices remain separate from runtime SBOMs.

## Fixed inputs and recipe

Source: upstream actionlint1.7.12 commit
`914e7df21a07ef503a81201c76d2b11c789d3fca`, tree
`ecee8c9c752f012b2da57a5fc59863624539b43b`; archive1646100bytes,
SHA256`454800bd4f854592bcfe79b161f71d56e35940eb7016e48a26dd356adc9d400a`.
All850 original file bytes, Git blobs and modes are frozen in
`tools/actionlint-build.lock.json`. No generators or upstream tests are run.
Original go.mod/go.sum are immutable; a separate actionlint.mod/actionlint.sum
selects the exact20-module graph, including x/sys0.44.0.

Overlay SHA256:

- mod: `551cd61e64ea59573ee0264e07a21b2db405f88ccfd0cac27c2e18a4b9e96daa`
- sum: `c239b0e641d4da3b7ee719414b8041902776a48cfff18be1ebc938dc6d53750f`

Only reuse the actually admitted project06 Linux-amd64 Go1.26.11 archive,
66999944bytes, SHA256
`9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec`,
and its separately admitted govulncheck modulev1.9.0. No second compiler,
Windows Go installation, unreviewed graph, go get/tidy/latest or automatic
compiler switching is allowed. Null source-held admission pins are a HOLD.

Four builds total: two fresh GOCACHE/output directories each for windows-amd64
and linux-amd64. Compile in the bounded Linux guest, with CGO0, GOAMD64v1,
GOMAXPROCS2, GOTOOLCHAINlocal, GOENVoff, GOWORKoff, GOTELEMETRYoff, GOAUTHoff,
GOVCS*:off and frozen SOURCE_DATE_EPOCH1774892837. Build module inputs offline
with canonical SumDB trust retained. Do not inherit Go/VCS/auth overrides.

```text
go build -mod=readonly -modfile=<sealed-overlay>/actionlint.mod -p=1
  -trimpath -buildvcs=false
  -ldflags="-s -w -buildid= -X github.com/rhysd/actionlint.version=1.7.12 -X github.com/rhysd/actionlint.installedFrom=maintainer-built-914e7df21a07-go1.26.11-xsys0.44.0"
  -o=<fresh-output>/actionlint[.exe] ./cmd/actionlint
```

This is a maintainer build, not an upstream-official patched actionlint release.
The Go/tool/module notice graph stays separate from application runtime SBOMs.

## Stage boundaries

`tools/build_actionlint.py` provides finite prepare/acquire/notices/graph/source-audit/
build/binary-audit phases. It currently cannot pass the tool-admission gate.
The actual producer handoff schema, auditor protocol and native filesystem
materialization must be verified before those paths can be claimed to work.
Actual source preparation and finite module acquisition/authentication have passed.
The remaining phases are source work, not evidence of executed scans/builds.

The authenticated20-module receipt is sealed at SHA256
`898c397ddcf3f8dbaea2248b1004bd4abe02b25bd6faf622a83da5e33d813644`:
18103560 raw bytes,4650 regular module-cache files and an actual signed SumDB
checkpoint. The real Go PID548/start46209 was stopped before exec, with actual
4GiB/CPU2/64-task/swap0 membership read back. The phase exited0 and the owned
service was collected before canonical lease release. This does not admit a
compiled module, auditor or actionlint artifact.

Each consuming phase requires the exact approved canonical lease protocol,
own token and real guest service membership. Actual aggregate limits are
4GiB memory, swap0, one CPU core and64tasks, checked before child creation.
Each bounded phase releases fairly only after all owned descendants/services
terminate and evidence is durable. Never steal a foreign lease or delete by age.

Input acquisition is finite to the20 reviewed modules:64MiB per input,1GiB
new input bytes,4GiB workspace. Complete raw archive/member identities and h1
checks precede materialization. A fresh admitted Go downloader authenticates
canonical SumDB signatures/tiles without a preexisting trusted go.sum/cache;
raw lookup HTTPS alone is not authentication. Its actual cached checkpoint,
module receipt and target package/init graph are frozen in reviewed source-held
pins before later consumer phases. No newly discovered module is auto-admitted.

Each build has1200seconds; each source/binary audit600seconds. Tool execution
has90seconds. Logs are bounded128MiB. Windows native validation uses an actual
aggregate Job with the child suspended until assignment/readback, memory4GiB,
one-CPU quota and64process limit; a Job around wsl.exe is not a guest cap.

Before executable admission, both source and exact-binary evidence must bind
source commit/tree, compiler, overlay, target, actual package/init closure,
buildinfo and a frozen current canonical advisory snapshot. The36 metadata
module-version matches are unresolved until individually disposed. An applicable,
unknown, malformed, incomplete or unbound finding is HOLD before --version.
Module absence must agree in actual source production closure and binary module
closure; no version-only, symbol-only or empty-JSON PASS is sufficient.

The independent checker uses source-held artifact and proof hashes. A candidate
manifest's PASS or recomputed self-hash cannot authorize bytes. Linux execution
uses a sealed memfd copy. Windows holds executable/ancestor identity through
spawn with write/delete denied. These guards cover project entry points;
they do not claim OS prevention of a person's manual executable invocation.

## Project05 observed evidence

The signed application checkpoint `90130fe` passed 51 source units on each OS,
retaining the original 39 and twelve new vectors. Each actual Windows/Linux
archive passed eight package checks and seven wire responses. The unchanged
Linux PostgreSQL matrix passed 14 cases, 23 commits and 1,866 independent point
queries. The new17-correction scenario passed19 SQL history rows,18 active
segments, one pre-correction point,14 post-correction points, one future denial,
continuations0/16/17, one replay and one conflict. The existing pinned/attacker
signature regressions passed eight tests and27 subprocess scenarios on each OS.
These facts belong to the application checkpoint; exact final archives have
their own manifests and delivery packet.

All50 consumer negatives passed in each required interpreter mode: normal,
-O and actual PYTHONOPTIMIZE=2, with optimize values0/1/2. The environment-mode
child had neither -I nor -E. There were zero candidate executions in all150
cases. Only after this prerequisite did each native OS execute the exact
admitted binary for version and default/direct valid/invalid workflow controls.
Those ten native invocations passed with actual per-consumer caps and teardown.
Project05 retained CPU1, memory4GiB, swap0 on Linux and64 tool processes; the
producer's CPU2 limit or native-workspace exception is not inherited.

The independent guard binds the original source, compiler, exact module graph,
source/binary scan streams, package and init evidence, reproducibility, notices
and primary advisory records. The Windows SDK DNS backport has a separate
whole-source binding; module absence alone does not dismiss a vendored SDK
package. The advisory database is the frozen primary snapshot observed at its
recorded time, not a future absence-of-vulnerabilities guarantee.

## Delivery boundary

Ordinary linting reads only an admitted bundle under
`artifacts/actionlint/<target>` and the source-held reference. Missing or
mismatched inputs fail closed; there is no vendor/cache/latest/download fallback.
The Go compiler, auditor, caches, source archives and linter binaries are excluded
from the application runtime packages and their three-component SPDX graph.
Only the recipe/guard/reference text is included as build-time source tooling.

The common public CI publication/import profile is still a separately gated,
unimplemented proposal. Current local proof does not establish hosted CI or
public preview.3 availability. The proposed path is an identity-bound shared
producer output, imported and checked before the existing policy job, preserving
its five-minute bound and all original native/release jobs. It must operate
without private E receipts and include real runner caps, exact immutable import
identities, reproduction and explicit CI/storage cost limits. No hosted dispatch,
push, tag, release or account metadata change follows from local admission.

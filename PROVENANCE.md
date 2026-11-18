# Verify provenance

Independently trusted key fingerprint:
`SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU`.

With a separately trusted copy of the source/verifier:
```sh
python tools/verify_downloads.py --directory DOWNLOAD_DIRECTORY --work NEW_VERIFY_DIRECTORY --trusted-fingerprint SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU --archive EXACT_SELECTED_ARCHIVE_FILENAME
```

A sibling downloaded key/verifier is not an independent trust root. Exactly one canonical SSH ed25519 key is accepted; injected keys/principals/comments and case-changed fingerprints fail. Signature and all present selected archive checks remain active under -O/PYTHONOPTIMIZE.

Signed commits/tags/checksums establish provenance under the pinned key, not Authenticode, production certification, byte-reproducible builds, a SLSA level, financial performance or exclusive ownership. NuGet normalized contentHash excludes signatures; SPDX checksums refer to actual raw signed .nupkg bytes. Never transfer the private key. Local source/build/runtime evidence, public native CI and actual public downloads are separate gates.

The [maintainer actionlint recipe](docs/ACTIONLINT-BUILD.md) has separate build-time provenance: upstream source commit914e7df21a07ef503a81201c76d2b11c789d3fca/treeecee8c9c752f012b2da57a5fc59863624539b43b, unchanged original Go manifests and an explicitly pinned x/sys0.44.0 sidecar graph. It is a maintainer build, with source-held independent admission pins, not an upstream-official patched release. No tool receipt or candidate self-hash substitutes for the signing trust root or the application download checks above.

## Sealed tooling release provenance

The shared input tag is tooling-actionlint-v1.7.12-go1.26.11-r1 in
pouriajamali/data-admission-gate. Its two ZIP hashes/sizes are pinned in the
reviewed source lock. Verify the file-namespace signed SHA256SUMS against the
independently trusted ED25519 fingerprint printed above and principal
pouriajamali. Candidate PASS/self-hashes and a co-downloaded key alone are not
trust anchors. The archive carries all original tooling notices plus the
Go Vulnerability Database CC-BY-4.0 license/attribution. Producer path strings
are observations; fresh runtime reads only reviewed source and archive-relative
inputs. See docs/ACTIONLINT-BUILD.md for controlled import/default/direct routes.

## Preview.4 direct maintenance release

The SDK11.0.100/net11.0/C#15 release uses original signed runtime11.0.0 bytes
and SDK-generated locks. Raw archive hashes, normalized NuGet content identities,
CMS/RFC3161 verification and current certificate/CRL/snapshot evidence retain
separate scopes. No package hash is relabeled between those meanings.

Local source/PID/start, native host and own kernel containment are required.
The host's observed compatibility does not establish hosted CI or new vendor
certification. Actions was not run by owner instruction.

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


The known ED25519 key signs SHA256SUMS in the file namespace. No GitHub
attestation or hosted-CI success is claimed for preview.4. Native Windows/Linux
archives and the exact Git source ZIP bind source625b133; later documentation
commits have a separate identity.

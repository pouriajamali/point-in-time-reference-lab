# Verify provenance

Independently trusted key fingerprint:
`SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU`.

With a separately trusted copy of the source/verifier:
```sh
python tools/verify_downloads.py --directory DOWNLOAD_DIRECTORY --work NEW_VERIFY_DIRECTORY --trusted-fingerprint SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU --archive EXACT_SELECTED_ARCHIVE_FILENAME
```

A sibling downloaded key/verifier is not an independent trust root. Exactly one canonical SSH ed25519 key is accepted; injected keys/principals/comments and case-changed fingerprints fail. Signature and all present selected archive checks remain active under -O/PYTHONOPTIMIZE.

Signed commits/tags/checksums establish provenance under the pinned key, not Authenticode, production certification, byte-reproducible builds, a SLSA level, financial performance or exclusive ownership. NuGet normalized contentHash excludes signatures; SPDX checksums refer to actual raw signed .nupkg bytes. Never transfer the private key. Local source/build/runtime evidence, public native CI and actual public downloads are separate gates.

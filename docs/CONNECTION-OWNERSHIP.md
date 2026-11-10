# Connection ownership on failed open

`Store` owns each newly allocated `NpgsqlConnection` until `OpenAsync` completes successfully. Only then does it return the connection to the caller's `await using` statement. If open fails or is cancelled, it awaits `DisposeAsync` before rethrowing the original exception. A secondary cleanup exception cannot replace that original failure. Successful open transfers ownership without disposing the returned object.

This is an ownership correction. It does not change SQL, transaction boundaries, connection strings, pooling (`false`), public APIs, dependency versions or business acceptance rules. It introduces a small internal generic observation seam, exposed only to the existing test assembly. No `NpgsqlDataSource` or resource pool was added.

## Executable counterexamples

The nine cases in [`ConnectionOwnershipTests`](../tests/Reference.Tests/ConnectionOwnershipTests.cs) cover:

- Successful transfer, with exactly one later disposal by the caller.
- Synchronous and asynchronous open failures: exactly one disposal and the same original exception.
- Cancellation: disposal and preservation of the original cancellation object and token.
- Asynchronous disposal: the failed operation cannot complete before cleanup finishes.
- Synchronous and asynchronous disposal failures: the original open exception remains observable.
- A real Npgsql connection on a reserved, non-listening loopback port: actual connection refusal followed by an `ObjectDisposedException` when reuse is attempted.
- A real Npgsql connection accepted by an owned loopback socket that sends no PostgreSQL response: cancellation during the handshake, the exact driver cancellation exception, and an `ObjectDisposedException` on subsequent reuse.

The socket tests use only temporary `127.0.0.1` endpoints and synthetic credentials. They require no external database. A closed connection state alone is not disposal evidence; attempted object reuse distinguishes the two. Npgsql may emit a cancellation token linked internally by the driver, so the real-driver test preserves the observed driver exception and token instead of assuming that token equals the caller's.

## Bounded observations

The red baseline extracts the original `await open; return` behavior into the observation seam, without adding cleanup. Against that baseline, eight new ownership cases fail while successful transfer and all existing domain cases pass. Adding failure cleanup makes the same test bytes pass on Windows x64 and native Linux x64 in the existing Ubuntu WSL environment: 39 tests in this repository. This is local test evidence; exact-commit public CI and release acceptance remain separate gates.

An initial test-build attempt failed xUnit's cancellation analyzer; bounded waits were corrected to accept the runner cancellation token without suppressing the analyzer. An initial sandboxed socket attempt was rejected by the environment and is not used as a connection-refusal result. The retained red/green observations use permitted loopback sockets.

These tests establish object ownership and exception behavior under the listed conditions. They do not measure a native memory/socket leak, production resource pressure, throughput, failover reliability or general database availability. The older published preview and its frozen architecture evidence remain historical until a separately tested release is accepted.

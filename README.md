# sedsprintf_cpp

C++ port of `sedsprintf_rs`, focused on the transport/runtime layers and the generated C ABI.

Version metadata is declared in `CMakeLists.txt` and `vcpkg.json`. The current
C++ port version is `4.0.1`, matching the documented upstream parity point.

This repo provides:
- schema-driven telemetry packet types and endpoint metadata
- packet serialization / deserialization helpers
- router and relay implementations with discovery and time sync support
- C ABI plus RAII-style C++ wrappers
- GoogleTest coverage for packet, router, relay, overlay, and C interop behavior

The implementation can be seeded from optional runtime schema and IPC overlay schemas. A default build is generic and only includes built-in control types; this repository's tests opt into `tests/schemas/default_test_schema.json` as a fixture.
Generated build artifacts live under `build/`.

## Features

- Discovery:
  learned reachable endpoints, transitive topology graphs, adaptive announce cadence, selective forwarding, topology export
- Time sync:
  announce/request/response packets, discovered source routing, local network-time setters
- Reliable transport:
  ACK/retransmit support with schema-driven reliable mode metadata
- Runtime configuration:
  schema registration/seeding, router/relay memory budgets, device identity, compression threshold, string/binary sizing, float string precision, handler retries, reliable retransmit timing, reliable cache limits, and router address mode are runtime APIs aligned with upstream v4.0.1. `MAX_STACK_PAYLOAD` remains a compile-time capacity because it changes inline payload layout.
- Link-local overlays:
  side-level isolation for software-bus / IPC-only traffic

Built-in control surfaces mirrored from the Rust runtime:
- data types:
  `TIME_SYNC_ANNOUNCE`, `TIME_SYNC_REQUEST`, `TIME_SYNC_RESPONSE`, `DISCOVERY_ANNOUNCE`,
  `DISCOVERY_TIMESYNC_SOURCES`, `DISCOVERY_TOPOLOGY`, `TELEMETRY_ERROR`
- endpoints:
  `TIME_SYNC`, `DISCOVERY`, `TELEMETRY_ERROR`
- reliable modes:
  `None`, `Ordered`, `Unordered` from schema/codegen metadata

## Build

Primary entrypoint:

```sh
python3 build.py test
```

That runs:
- CMake configure with `compile_commands.json`
- `clang-tidy`
- project build
- `ctest`
- codegen verification

## Layout

- `src/`
  core runtime, wrappers, and generated-schema integration
- `tests/`
  GoogleTest unit/system tests and codegen checks
- `tests/schemas/`
  checked-in schema fixtures for tests and codegen verification
- `scripts/generate_schema.py`
  schema/codegen driver
- `docs/`
  mirrored public-facing module documentation adapted from the Rust repo
- `examples/`
  buildable C ABI examples matching upstream runtime config, time sync,
  routing, and managed-variable/E2E topics

## Status

Rust/Python interop layers are intentionally omitted here.
Discovery, topology export, and discovery-driven routing semantics are aligned with the Rust runtime.
Remaining parity work is primarily non-C++ bindings/doc surfaces and broader regression coverage.

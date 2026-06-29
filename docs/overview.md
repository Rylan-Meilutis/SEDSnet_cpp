# Overview

`sedsprintf_cpp` mirrors the core telemetry runtime from `sedsprintf_rs` in C++.

Main responsibilities:
- schema-derived data type and endpoint metadata
- packet validation and string formatting
- compact wire serialization with CRC and reliable headers
- router / relay forwarding behavior
- built-in discovery and time sync control traffic, including topology export JSON through the C ABI

Public entrypoints:
- C ABI in `sedsprintf.h`
- C++ wrappers in `src/packet.hpp`, `src/router.hpp`, `src/relay.hpp`, `src/discovery.hpp`, and `src/timesync.hpp`

Non-goals in this repo:
- Rust FFI implementation
- Python bindings

Runtime metadata comes from:
- direct endpoint/type registration through the C ABI
- JSON bytes/file registration through the C ABI
- optional startup seed files supplied through `SEDSNET_STATIC_SCHEMA_PATH` / `SEDSPRINTF_SCHEMA_PATH`
- optional IPC overlay seed files supplied through `SEDSNET_STATIC_IPC_SCHEMA_PATH` / `SEDSPRINTF_IPC_SCHEMA_PATH`

Without a schema path the build is generic and emits only the built-in control types and endpoints. The checked-in sample telemetry schema is a test fixture at `tests/schemas/default_test_schema.json`.

Runtime APIs also configure router/relay memory budgets, device identity, compression threshold, string/binary sizing, float string precision, handler retries, reliable retransmit timing, reliable cache limits, and router address mode. `MAX_STACK_PAYLOAD` remains a compile-time capacity because it changes inline payload layout.

The build regenerates:
- `build/generated/sedsprintf.h`
- `build/generated/generated_schema.hpp`

Overlay builds regenerate parallel files under `build/generated_overlay/`.

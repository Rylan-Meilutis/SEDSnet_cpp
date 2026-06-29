# Upstream feature parity checklist

This list is the working audit against `../sedsnet`. A checked item means this
C++ port has behavior-level tests, not only matching symbols.

## Core ABI and Build

- [x] Upstream `sedsnet.h` public header name and built-in-only enums.
- [x] Upstream `SEDSNET_*` CMake/build variables and targets.
- [x] Runtime schema seeding from `SEDSNET_STATIC_SCHEMA_PATH` and
  `SEDSNET_STATIC_IPC_SCHEMA_PATH`.
- [x] Upstream public `seds_*` function names compile and link.
- [x] No default app schema is required; repository tests opt into a fixture
  schema explicitly.
- [x] Add upstream wrapper header filenames `sedsnet_c_wrapper.h` and
  `sedsnet_cpp_wrapper.hpp`.
- [x] Port upstream `sedsnet_c_wrapper.c` global router/relay convenience API.
- [x] Runtime tuning C ABI matches upstream get/set validation, defaults, and
  behavior wiring for device identity, string/binary sizing, float precision,
  handler retries, reliable limits, and compression threshold.
- [x] v4.0.1 runtime-config changelog parity: remaining host/prebuilt tuning
  knobs are runtime editable across the C/C++ ABI. `MAX_STACK_PAYLOAD` remains
  compile-time-only because it changes inline payload layout, matching upstream.
- [x] Router/relay runtime memory constructor APIs match upstream signatures and
  bad-argument behavior.

## Wire, Router, Relay

- [x] v4 packed framing, runtime IDs, compact endpoint bitmap, and ACK-only
  reliable link frames.
- [x] Mixed Rust/C++ normal telemetry, reliable telemetry, discovery, and time
  sync interop through routers and relays.
- [ ] Compact side transport profiles: header templates, template eviction,
  chunking/reassembly, omitted unchanged timestamps.
- [ ] Link-probe samples affect routing/throttling and runtime stats.
- [x] Leave announcements prune remote topology immediately.
- [x] Client stats JSON exposes upstream fields for discovered clients and `null`
  for unknown/left clients.
- [x] Runtime stats JSON exposes upstream fields for sides, routes, queues,
  reliability, and discovery.
- [ ] Runtime stats counters match upstream exactly.
- [x] Memory layout JSON exposes upstream queue/cache fields.
- [x] Memory layout JSON reflects per-instance runtime memory budgets.
- [x] v4.0.1 small runtime memory budget regressions cap queued router/relay
  state below the configured shared budget.
- [ ] Memory layout byte accounting matches upstream exactly.

## Runtime Schema

- [x] Runtime endpoint/type registration from direct C calls and JSON bytes/file.
- [x] Env-seeded runtime schema tests.
- [x] Preserve descriptions/doc strings in runtime metadata APIs.
- [x] Protect built-ins from removal/shape mutation.
- [x] Enforce upstream conflict/type-shape rules.
- [ ] Schema discovery snapshot encode/decode and mixed Rust/C++ merge interop.
- [x] Handler registration auto-creates missing placeholder endpoints.

## Managed and Network Variables

- [x] Enable/disable managed variable types.
- [x] Network variable read/write permission policy.
- [x] Seed/set/cache packed managed values.
- [x] Request stale/missing values and reply with cached values.
- [x] Invoke network-variable update callbacks.
- [x] Mixed Rust/C++ managed-variable interop through routers.
- [ ] Mixed Rust/C++ managed-variable interop through relays.

## P2P

- [x] Address/hostname resolution for learned P2P peers.
- [x] Runtime router address assignment C ABI (`dynamic`, `requested`,
  `static`) matches upstream validation.
- [x] P2P datagram send/receive via `SEDSNET_P2P_MESSAGE`.
- [x] P2P stream open/data/close/reset session state.
- [x] Mixed Rust/C++ P2P datagram and stream SYN/SYN-ACK interop.
- [ ] Discovery-address conflict resolution and automatic P2P address-book
  convergence match upstream exactly.

## Cryptography

- [x] Guarded C provider symbols exist and dispatch provider callbacks.
- [x] Software fallback key registration/seal/open.
- [x] Managed credential issue/verify/tamper/expiry behavior.
- [ ] Router E2E encryption policy enforcement.
- [ ] Mixed Rust/C++ encrypted payload interop.

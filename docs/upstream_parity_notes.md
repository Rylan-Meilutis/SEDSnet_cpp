# Upstream SEDSnet parity notes

This C++ port has been moved to the upstream `../sedsnet` C ABI shape for the
public header, CMake-facing names, runtime schema seeding, packed wire format,
and mixed Rust/C++ interop tests. The upstream public API authority used for this
pass is `../sedsnet/C-Headers/sedsnet.h` plus the C/C++ wrapper headers in
`../sedsnet/c-wrapper/`.

## Completed in this parity pass

- Added generated `C-Headers/sedsnet.h` with upstream built-in-only public
  enums. User schema IDs now live in the runtime ID space (`100+`), while
  `sedsprintf.h` remains as a legacy compatibility include.
- Added upstream `SEDSNET_*` CMake/cache variables, `sedsnet::sedsnet`,
  optional `sedsnet::c_wrapper`/`sedsnet::cpp_wrapper` targets, and updated
  `build.py` to prefer `static_schema_path` / `static_ipc_schema_path`.
- Added once-only runtime schema seeding from `SEDSNET_STATIC_SCHEMA_PATH` and
  `SEDSNET_STATIC_IPC_SCHEMA_PATH`, with explicit bytes/file registration
  covered by tests.
- Moved generated constants and runtime metadata to upstream ID conventions:
  built-in control IDs remain fixed and user types/endpoints start at `100`.
- Added all upstream `seds_*` public function names present in
  `../sedsnet/C-Headers/sedsnet.h`, including packed aliases, runtime metadata
  APIs, lifecycle aliases, profile APIs, P2P/managed-variable APIs, and
  guarded cryptography provider API symbols.
- Updated v4 packed serialization/deserialization, ACK-only reliable frames,
  and runtime wire-ID mapping for Rust compatibility.
- Expanded interop so the C++ router/relay can participate in mixed Rust/C++
  router and relay paths for normal, reliable, discovery, and time-sync traffic.
- Added `sedsprintf_upstream_api_parity_test` and
  `sedsprintf_runtime_env_schema_test`.
- Matched the upstream v4.0.1 runtime-configuration release notes: active nodes
  can update device identity, compression threshold, static string/binary
  sizing, float string precision, handler retry count, reliable retransmit
  timing, reliable cache limits, router address mode, and router/relay memory
  budgets at runtime. The only remaining compile-time tuning capacity is
  `MAX_STACK_PAYLOAD`, which upstream also keeps compile-time because it changes
  inline payload layout.

## Required API surface updates

- Remove the remaining internal dependency on generated `generated_schema.hpp`
  for the library's default example schema. The public `sedsnet.h` no longer
  exposes generated user enums, but the port still uses codegen internally for
  legacy examples/tests.
- Runtime JSON registration accepts `description` and legacy `doc` fields,
  auto-upgrade legacy `broadcast_mode: "Never"` to `link_local_only: true`,
  and use the same ID conventions as upstream v4 (`DataType::named("GPS_DATA")`
  maps to runtime ID 100 for the default schema, built-in control IDs remain
  fixed).
- Handler registration auto-creates missing runtime endpoints as named
  placeholders. Remaining schema-discovery work should include those
  placeholders in advertised snapshots.
- Schema discovery sync must advertise and merge runtime endpoint/type
  definitions, resolve ID/name conflicts deterministically, and reject type
  shape conflicts on direct registration.
- Upstream wrapper header filenames now exist, the header-only C++ helper API is
  available through `sedsnet_cpp_wrapper.hpp`, and upstream
  `sedsnet_c_wrapper.c` is ported into the optional `sedsnet::c_wrapper` target
  with router/relay wrapper smoke coverage.
- Static JSON config is now only runtime seeding. Default builds no longer need
  a repository-local application schema, and test schemas live under
  `tests/schemas/`.

## Feature gaps needing explicit behavior

- Direct C runtime endpoint/type registration, removal, JSON bytes/file
  registration, and env seeding now mutate the process-local metadata registry
  and are covered by tests. Metadata descriptions/docs, link-local endpoint
  flags, priority/reliability/class fields, protected built-ins, remove-by-name,
  endpoint removal cascades, and upstream conflict/type-shape rejection are
  covered by C API parity tests.
- Rust interop checkout preparation now applies narrow compatibility patches to
  the temporary copied upstream tree when the sibling Rust repo has queue-memory
  constants or relay memory initialization edits half-applied. These patches are
  limited to the test checkout under `build/` and keep mixed Rust/C++ interop
  runnable against the current sibling repo state.
- Network-variable latest-value caching must match upstream: enable managed or
  network variables with read/write policy, set/get packed values, refresh stale
  or missing cache entries via internal request packets, and invoke update
  callbacks for inbound changes.
- P2P datagram and stream APIs now use ordered `SEDSNET_P2P_MESSAGE` frames,
  support learned hostname/address resolution, and are covered by C API and
  Rust/C++ interop tests. Remaining work: upstream-exact discovery-address
  conflict resolution and automatic address-book convergence.
- Crypto APIs are gated upstream by `SEDS_ENABLE_CRYPTOGRAPHY`; the public
  provider symbols dispatch provider callbacks, software fallback keys seal/open
  with the upstream HMAC stream/tag format, and managed credentials issue/verify
  the upstream 80-byte credential layout with tamper and expiry checks. Remaining
  work: E2E encryption policy enforcement and encrypted mixed-network interop.
- Compact side transport profiles/header templates/chunking should match
  upstream fixed-size packed splitting/reassembly and header-template behavior.
- Link-probe sample APIs should seed adaptive routing and slow-link control-plane
  throttling, not just validate side IDs.
- Leave announcements now prune direct and transitive remote topology
  immediately. Client stats JSON now follows the upstream field shape for
  discovered clients and returns `null` for unknown or left senders. Runtime
  stats and memory layout JSON now expose the upstream C ABI field shape for
  sides, routes, queues, reliability, discovery, and queue/cache memory fields.
  Remaining stats/export work: exact runtime packet/byte counters, exact memory
  byte accounting, and exact topology JSON field parity.

## Test coverage to add

- Broader behavior tests for encrypted E2E policy, relay-mediated managed/P2P
  flows, and discovery-address conflict handling.
- Runtime-schema tests covering:
  schema memory budget accounting and schema discovery merge/conflict behavior
  across mixed Rust/C++ networks.
- Mixed-network interop tests still need schema sync, leave pruning, and
  relay-mediated managed/P2P coverage beyond the current
  normal/reliable/discovery/time-sync router/relay matrix.

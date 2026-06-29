# Examples

The C++ port mirrors the upstream SEDSnet example topics through buildable C
ABI examples under `examples/`.

Build:

```sh
cmake -S . -B build/examples -DSEDSNET_ENABLE_TESTS=OFF -DSEDSNET_ENABLE_EXAMPLES=ON
cmake --build build/examples
```

Run examples that use `GPS_DATA`, `RADIO`, or other fixture names with a runtime
schema seed:

```sh
SEDSNET_STATIC_SCHEMA_PATH=$PWD/tests/schemas/default_test_schema.json \
  ./build/examples/sedsnet_timesync_example
```

Available examples:

- `runtime_config_example.c`: upstream v4.0.1 runtime configuration for active
  device identity, tuning, memory budgets, time-sync role, router address mode,
  and memory-layout export.
- `timesync_example.c`: local endpoint handlers, packet logging, time-sync
  announce/request maintenance, and network-time reads.
- `routing_example.c`: weighted route selection and type-specific route
  overrides.
- `managed_variables_e2e_example.c`: runtime schema registration, managed
  network-variable caching, and optional E2E crypto provider hooks through the
  C wrapper.

The repository does not require a default application schema at build time.
Schemas are runtime metadata: seed with environment variables, register JSON
bytes/files, or call endpoint/type registration APIs directly.

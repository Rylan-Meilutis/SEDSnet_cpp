# SEDSnet C++ Port Examples

These examples mirror the upstream SEDSnet example topics using this port's C
ABI and optional C wrapper.

Configure with examples enabled:

```sh
cmake -S . -B build/examples -DSEDSNET_ENABLE_TESTS=OFF -DSEDSNET_ENABLE_EXAMPLES=ON
cmake --build build/examples
```

Run with a runtime schema seed:

```sh
SEDSNET_STATIC_SCHEMA_PATH=$PWD/tests/schemas/default_test_schema.json \
  ./build/examples/sedsnet_timesync_example
```

Examples:

- `runtime_config_example.c`: device identity, runtime tuning, memory budgets,
  time-sync role, router address assignment, and memory-layout export.
- `timesync_example.c`: local handlers, time-sync configuration, periodic
  control traffic, packet logging, and network-time reads.
- `routing_example.c`: weighted route selection and type-specific routing.
- `managed_variables_e2e_example.c`: runtime schema registration, managed
  network variables, and optional cryptography provider hooks.

The checked-in schema under `tests/schemas/` is only a fixture. A default build
is generic and can run with no application schema, then register endpoint/type
metadata at runtime through the C ABI.

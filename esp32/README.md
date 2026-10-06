# esp32/ — DTN node firmware for ESP32 (issue #39)

From-scratch firmware that implements the Module B node contract of
`docs/protocol.md` on ESP32 silicon, as an optional, fully interoperable
alternative platform to the Raspberry Pi node (`node/`). The two platforms
are peers: every deployer picks per node, and the network treats them
identically — same SSID, same origin (`http://offgrid.local:8080` at
`10.42.0.1`), same API, same limits, same error shapes.

The normative contract is `docs/protocol.md`; the design record for this
firmware (framework choice, board targets, storage engine, RAM/flash budgets,
the phased plan and its status) is `docs/esp32-design.md`. Board hardware
matrix: `docs/esp32-models.md`.

## Layout

```
esp32/
├── components/
│   ├── dtn_core/      # PORTABLE CORE — no ESP-IDF includes. Envelope
│   │                  # validation (§10.5/§15.3), limits (§8.1), the sync
│   │                  # processing order (§10.4), canonical-host logic
│   │                  # (§10.2), budget/token-bucket math, the streaming
│   │                  # JSON reader, the flash storage engine (§9 contract)
│   │                  # and the capabilities/health document assembly.
│   │                  # Compiles and unit-tests on the CI host (host/).
│   └── dtn_node/      # ESP-IDF adapters: httpd handlers (8080 + 80),
│                      # dns_server, LittleFS wiring, esp_task_wdt,
│                      # snapshot cache, janitor task.
├── main/              # app entry: netif reconfigured to 10.42.0.1, softAP
│                      # "offgrid-messages" + DHCP/DNS bring-up, embedded
│                      # SPA assets (served verbatim from node/web), tasks.
├── partitions_16mb.csv / partitions_4mb.csv   # reference / minimum layouts
└── sdkconfig.defaults(.esp32s3/.esp32)
```

`dtn_core` is deliberately free of any `esp_*` include: everything that can
be tested without hardware IS tested without hardware (`make test-esp32-core`
runs the host suite; it is part of `make test`). The IDF side (`dtn_node`,
`main`) is kept thin: glue, not logic.

## Building

```
make firmware            # both reference (esp32s3) and minimum (esp32) targets
```

wraps the documented `idf.py` invocation (ESP-IDF v5.5; see
`docs/esp32-design.md` §5). `make` stays a convenience: the raw command is in
the Makefile recipe and in `docs/BUILD.md`. CI builds both targets and the
merged flashable image on demand (`gh workflow run test --ref <branch>` —
the workflow is manual-dispatch only per the coordination notice in
`AGENTS.md`).

## Status

Phased implementation tracked in `docs/esp32-design.md` §8 (plan) — phases
0–2 are host-verifiable and land with their unit tests; phases 3–5 carry the
on-hardware acceptance register (`docs/esp32-design.md` §9) that must be
executed on real boards before a release tag ships the firmware.

# Changelog

## 0.2.0 — 2026-07-12

- Added a signed seven-dimension Evidence Gateway for OLP Canon and pinned Agent
  Receipts v0.5 inputs.
- Added stateful replay, cross-run, parent, generation, session, and challenge
  checks without mutating verifier sessions during evaluation.
- Added independent outcome witnesses and prior-verdict-bound causal uptake.
- Added a chain-enforcing local SQLite wallet, unified CLI, local stdio MCP proxy,
  and loopback-only browser verifier.
- Added receiver-mode MCP forwarding that gates exact tool-response uptake and
  records exact request/response hashes without rewriting protocol messages.
- Added a neutral four-profile, nine-attack benchmark with separate measurements
  and no combined score.
- Preserved the original self/provisional OTel capture boundary and Node
  conformance verifier.
- Fixed the isolated package check on clean Python 3.12 runners by letting the
  declared PEP 517 build environment install `setuptools.build_meta`.

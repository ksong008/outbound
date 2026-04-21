# XHTTP H3 Parity Memo

Branch: `personal/stable`
Repo: `/Users/Shaka/New project/outbound`
Date: `2026-04-21`

## Goal

Track the remaining work needed to bring outbound's `xhttp` implementation,
especially `h3 + auto`, closer to Xray's official `splithttp` behavior.

This memo is for:

- official parity comparison
- ordered implementation checklist
- per-step change recording

This memo intentionally focuses on transport behavior and does not record
specific user traffic hit logs.

## Official References

Primary discussion:

- `XHTTP: Beyond REALITY`
  - `https://github.com/XTLS/Xray-core/discussions/4113`

Primary source files:

- `/tmp/xray-core/transport/internet/splithttp/dialer.go`
- `/tmp/xray-core/transport/internet/splithttp/client.go`
- `/tmp/xray-core/transport/internet/splithttp/mux.go`
- `/tmp/xray-core/transport/internet/splithttp/upload_queue.go`

Current outbound implementation:

- `/Users/Shaka/New project/outbound/transport/xhttp/xhttp.go`
- `/Users/Shaka/New project/outbound/transport/xhttp/xhttp_test.go`

## Current Baseline

Already aligned or mostly aligned:

- `auto` mode default:
  - normal TLS -> `packet-up`
  - REALITY -> `stream-one` or `stream-up`
- request lifetime detached from `DialContext` cancellation
- per-stream deadline behavior treated as no-op
- `stream-up/stream-one` release timing moved closer to official split transport
- `h2 + stream-up` is currently the most stable line
- `h3 + auto` can carry real traffic, but still shows stability problems

Key remaining gap:

- official Xray uses a shared `DialerClient + XmuxManager` lifecycle for all
  HTTP versions
- outbound still uses a more local and simplified H3 client lifecycle

## Parity Checklist

Done:

- [x] Align `auto` mode default with official `splithttp`
- [x] Use `context.WithoutCancel(ctx)` for HTTP request lifetime
- [x] Make deadline behavior no-op
- [x] Move `stream-up/stream-one` release timing closer to official behavior

In progress:

- [~] H3 shared client lifecycle parity
  - goal:
    - move closer to official `DialerClient/XMUX` lifecycle
    - avoid per-connection H3 transport churn
  - current status:
    - per-dialer H3 request-client reuse has been introduced
    - H3 request clients now self-close on transport errors so the next use can rebuild
    - basic H3 request counting / retirement semantics have started to follow XMUX-style rules
    - `packet-up` upload no longer has to stay bound to a single fixed H3 client for the entire connection
    - still not full global `XmuxManager` parity

- [ ] H3 client eviction and rotation semantics
  - match official ideas around:
    - `IsClosed`
    - `OpenUsage`
    - `LeftRequests`
    - `UnreusableAt`
  - especially important for `h3 + auto -> packet-up`

- [ ] `packet-up` upload lifecycle parity
  - compare our `packetBatchUploader` with official:
    - `uploadQueue`
    - `PostPacket`
    - pipe-backed batching and rollover
  - confirm whether we still miss any official retry / rollover behavior

- [ ] H3 download-side lifecycle parity
  - compare our async download path with official `OpenStream`
  - verify reader handoff and stream lifetime under browser-like churn

- [ ] QUIC parameter parity review
  - compare with official handling of:
    - `MaxIdleTimeout`
    - `KeepAlivePeriod`
    - `MaxIncomingStreams`
    - receive windows
    - path MTU options
    - congestion settings
    - UDP hop support

- [ ] H3 + auto regression matrix
  - cover at least:
    - simple HTTP request
    - repeated page refresh
    - browser-like concurrent short requests
    - H3 error and client rebuild behavior

- [ ] H3 + stream-up stability review
  - separate from `h3 + auto`
  - treat as its own line after `h3 + auto` lifecycle gaps are clearer

## Ordered Execution Plan

1. Finish the H3 shared-client lifecycle comparison against official `DialerClient/XMUX`.
2. Normalize client eviction and rotation semantics.
3. Re-check `packet-up` upload queue parity.
4. Re-check H3 download/open-stream lifetime handling.
5. Review QUIC parameter gaps.
6. Run regression validation and only then sync the full chain again.

## Change Log

### 2026-04-21

Initial parity memo created.

Snapshot of current understanding:

- `h2 + stream-up` is currently the best baseline for stable browsing tests.
- `h3 + auto` is functionally working, but still unstable.
- the main remaining delta appears to be lifecycle parity, not basic feature
  support.

Recent outbound-side work already in the branch:

- `53cb464` `fix(xhttp): reuse h3 clients across sessions`
  - introduces per-dialer H3 request-client reuse
  - closes shared H3 clients on transport error so the next use can rebuild
  - this is a step toward official lifecycle parity, but not the end state

- local follow-up after `53cb464`
  - H3 request-client management was pushed closer to XMUX-style semantics:
    - entry tracking now includes:
      - active usage
      - request budget
      - reuse budget
      - time-based retirement
    - `packet-up` upload can reacquire H3 request clients per batch instead of staying pinned
      to one fixed client for the whole connection
  - local validation:
    - `PATH=/tmp/gotool.UoBUAX/go/bin:$PATH GOTOOLCHAIN=local go test -timeout 90s ./transport/xhttp`
    - passed

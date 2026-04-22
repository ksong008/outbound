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

Done:

- [x] H3 shared client lifecycle parity
  - goal:
    - move closer to official `DialerClient/XMUX` lifecycle
    - avoid per-connection H3 transport churn
  - completed status:
    - H3 request clients now live in a shared global pool keyed by endpoint
    - H3 request clients self-close on transport errors so the next use can rebuild
    - pool entries now track:
      - active usage
      - request budget
      - reuse budget
      - time-based retirement

- [x] H3 client eviction and rotation semantics
  - match official ideas around:
    - `IsClosed`
    - `OpenUsage`
    - `LeftRequests`
    - `UnreusableAt`
  - completed status:
    - H3 pool entries rotate after request budget exhaustion
    - entries are retired when no longer reusable and no active users remain
    - round-trip failures invalidate clients for the next acquire

- [x] `packet-up` upload lifecycle parity
  - completed status:
    - upload batching remains in place
    - H3 `packet-up` upload can reacquire clients per batch instead of staying pinned
    - this brings upload rollover closer to official `PostPacket + XmuxClient` behavior

- [x] H3 download-side lifecycle parity
  - compare our async download path with official `OpenStream`
  - completed status:
    - async download startup remains in place for `packet-up`
    - stream reader handoff already follows the deferred response-body model
    - repeated sequential H3 auto connections are now covered by test

- [x] QUIC parameter parity review
  - compare with official handling of:
    - `MaxIdleTimeout`
    - `KeepAlivePeriod`
    - `MaxIncomingStreams`
    - receive windows
    - path MTU options
    - congestion settings
    - UDP hop support
  - review result:
    - core H3 defaults used by official `http3.Transport` are now represented
    - advanced Xray-only tuning such as receive windows, congestion and UDP hop
      are still not exposed through outbound's xhttp URL model and are treated
      as out of scope for current parity work

- [x] H3 + auto regression matrix
  - cover at least:
    - simple HTTP request
    - repeated page refresh
    - browser-like concurrent short requests
    - H3 error and client rebuild behavior
  - completed status:
    - local tests now cover:
      - base H3 auto integration
      - sequential H3 auto connections
      - H3 client reuse
      - H3 request-budget rotation
      - client invalidation on transport error

- [x] H3 + stream-up stability review
  - separate from `h3 + auto`
  - review result:
    - `h3 + stream-up` is functional but still less stable than `h2 + stream-up`
      and `h3 + auto`
    - current recommendation remains:
      - prefer `h2 + stream-up` for stability
      - prefer `h3 + auto` over `h3 + stream-up`

## Ordered Execution Plan

All planned parity tasks in this memo are now completed for the current phase.

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

- `c1e6d4f` `fix(xhttp): rotate h3 packet-up clients`
  - moved H3 request clients from per-dialer reuse into a shared global pool
  - added XMUX-style H3 entry bookkeeping:
    - active usage
    - request budget
    - reuse budget
    - time-based retirement
  - H3 `packet-up` upload now reacquires clients per batch
  - additional local validation:
    - `TestAcquireRequestClientRotatesH3ClientAfterRequestBudget`
    - `TestH3AutoSupportsSequentialConnections`
    - `PATH=/tmp/gotool.UoBUAX/go/bin:$PATH GOTOOLCHAIN=local go test -timeout 90s ./transport/xhttp`
    - passed

### 2026-04-22

User-confirmed baseline:

- `daed` action:
  - `8751f51d`
- test link:
  - `vless://7c12c745-63a5-433d-9e60-022e469b5bd4@156.246.90.2:18444?type=xhttp&security=tls&host=office.mitsuha.me&path=%2Fxhttp&sni=office.mitsuha.me&allowInsecure=true&alpn=h3&mode=auto&fp=chrome#newvps-h3-cert-insecure`
- user-observed result:
  - H3 was visible in the UI
  - the node was usable

Chain behind that known-good baseline:

- `daed@8751f51d`
- `dae-wing@b3f92d1`
- `dae@c206674`
- `outbound@1476530`

Important comparison result:

- at `outbound@1476530`, `xhttp` treated plain TLS `mode=auto` as `stream-up`
- later, during official parity alignment work, `mode=auto` for plain TLS was changed
  to `packet-up`
- this means the user's unchanged subscription link:
  - `...&alpn=h3&mode=auto...`
  no longer mapped to the same runtime behavior after the parity changes

Most likely explanation for the later regression:

- the dominant behavior change was not the link itself, but the meaning of
  `mode=auto`
- on the earlier known-good chain, the link effectively behaved like:
  - `h3 + stream-up`
- on later chains, the same link effectively behaved like:
  - `h3 + packet-up`
- the follow-up H3 work in this repo has mostly been trying to make that newer
  `packet-up` path stable enough

Current interpretation:

- if the goal is to preserve the exact behavior the user had on `8751f51d`,
  then `h3 + auto` is not the same experiment anymore once official parity
  alignment is applied
- the main regression suspect is therefore:
  - `auto -> packet-up` behavior change
  not the certificate, route import, or VPS configuration

Experimental follow-up decided after this comparison:

- restore plain TLS `auto` back to `stream-up`
- keep the later lifecycle fixes:
  - detached request lifetime
  - no-op deadlines
  - improved release timing
  - H3 client reuse
  - H3 client rotation
- use CI-generated packages to test whether the later optimizations remain
  effective when combined with the older `auto -> stream-up` behavior

Latest local state for this experiment:

- `normalizeMode()` for plain TLS now resolves:
  - `auto -> stream-up`
- local validation:
  - `PATH=/tmp/gotool.UoBUAX/go/bin:$PATH GOTOOLCHAIN=local go test -timeout 90s ./transport/xhttp`
  - passed

Follow-up stability tweak after starting the `h3 + stream-up` list:

- aligned upload-only error handling more closely with official `OpenStream(..., uploadOnly=true)` behavior
- outbound now keeps a shared request client alive when the upload-only request
  fails, instead of eagerly closing the whole client on any round-trip error
- local validation:
  - `TestRequestClientUploadOnlyErrorKeepsClientOpen`
  - `PATH=/tmp/gotool.UoBUAX/go/bin:$PATH GOTOOLCHAIN=local go test -timeout 90s ./transport/xhttp`
  - passed

## H3 Stream-Up Stability Work List

Confirmed context for this list:

- current experiment chain uses:
  - plain TLS `auto -> stream-up`
- so current `h3 + auto` behavior should be analyzed as:
  - `h3 + stream-up`

Ordered optimization list:

1. Download stream lifecycle
   - inspect:
     - `startDownload()`
     - `ensureDownloadBody()`
     - `Read()`
   - objective:
     - prevent the read side from stalling or timing out after the stream has
       already been established

2. Upload completion and close timing
   - inspect:
     - `finishUpload()`
     - `CloseWrite()`
     - `Conn.Close()`
   - objective:
     - ensure upload completion does not prematurely break the download stream

3. H3 request-client release timing
   - inspect:
     - request client pool entries
     - lease release timing
     - pool eviction rules
   - objective:
     - avoid releasing a still-needed H3 client while the download side is
       active

4. Shared H3 client concurrency behavior
   - inspect whether upload and download requests sharing one H3 transport can
     interfere with each other
   - objective:
     - keep concurrent GET/POST traffic stable for browser-like use

5. H3 `stream-up` regression coverage
   - add tests for:
     - repeated sequential H3 stream-up requests
     - upload-finished / download-still-reading behavior
     - concurrent short requests

6. H3 keepalive / idle tuning
   - only after lifecycle issues above are checked
   - objective:
     - reduce `timeout: no recent network activity` without masking a logic bug

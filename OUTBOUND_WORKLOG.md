# Outbound Worklog

Branch: `personal/stable`
Repo: `/root/project/outbound`
Date: `2026-05-03`

## Purpose

This worklog is the current top-level ledger for outbound-side audit and
optimization work.

Historical memos remain useful as background:

- `OUTBOUND_OPTIMIZATION_MEMO.md`
- `XHTTP_H3_PARITY_MEMO.md`

Those files capture earlier implementation phases. This file records the
current baseline, audit conclusions, validation, and next-step priorities.

## Current Baseline

- branch: `personal/stable`
- remote tracking: `origin/personal/stable`
- working tree status at creation time: clean
- HEAD at creation time:
  - `3535c49` `fix(vision): return error for unsupported tls conn`

Current review scope:

- `transport/xhttp/xhttp.go`
- `transport/xhttp/xhttp_test.go`
- `dialer/v2ray/v2ray.go`

Audit style for the current round:

- review first
- no code changes yet
- compare local implementation against latest stable mihomo behavior where useful

## 2026-05-03 Audit: outbound / xhttp optimization

### External reference baseline

Reference target used in this round:

- mihomo latest stable release: `v1.19.24`
- published at: `2026-04-20T01:56:58Z`

Primary reference links:

- `https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.24`
- `https://github.com/MetaCubeX/mihomo/blob/v1.19.24/transport/xhttp/client.go`
- `https://github.com/MetaCubeX/mihomo/blob/v1.19.24/transport/xhttp/config.go`
- `https://github.com/MetaCubeX/mihomo/blob/v1.19.24/common/convert/v.go`
- `https://github.com/MetaCubeX/mihomo/blob/v1.19.24/adapter/outbound/vless.go`

### Findings

#### 1. `packet-up` batching semantics are behind latest mihomo

Priority: high

Local implementation currently uses:

- fixed pre-flush delay:
  - `transport/xhttp/xhttp.go:1773`
- packet batch uploader path:
  - `transport/xhttp/xhttp.go:1782`
- sleep-before-flush logic:
  - `transport/xhttp/xhttp.go:2088`
- sleep-after-send gap:
  - `transport/xhttp/xhttp.go:2147`

Current behavior is closer to:

- wait a fixed delay
- flush a batch
- sleep the configured gap after send

Latest mihomo behavior instead uses `scMinPostsIntervalMs` as a timer-driven
merge window for upload batching.

Why this matters:

- current request rhythm is more rigid
- the new request-shaping knobs are not fully realized
- CDN / reverse-proxy facing behavior may diverge from upstream expectations

#### 2. `HTTP/1.1` mode is not actually implemented

Priority: medium-high

Relevant local refs:

- `transport/xhttp/xhttp.go:356`
- `transport/xhttp/xhttp.go:742`
- `transport/xhttp/xhttp.go:938`
- `transport/xhttp/xhttp.go:945`

Current state:

- exact `h3` can switch into the H3 path
- non-H3 traffic still falls into the H2-oriented client path
- there is no real dedicated `http/1.1` transport mode

Risk:

- config may appear accepted while behavior still follows H2-only assumptions
- this can cause silent mismatch when upstream configs start relying on
  `http/1.1` mode semantics

#### 3. Default request headers are too sparse

Priority: medium

Relevant local refs:

- `transport/xhttp/xhttp.go:383`
- `transport/xhttp/xhttp.go:616`
- `transport/xhttp/xhttp.go:625`

Current state:

- only user-supplied `extra.Headers` are copied
- there is no built-in browser-like default header profile

Compared with latest mihomo:

- mihomo has moved default xhttp headers closer to normal `fetch` traffic

Why this matters:

- weaker traffic camouflage
- more behavior variance across CDN / reverse-proxy deployments

#### 4. `downloadSettings.xhttpSettings.extra` is still rejected

Priority: medium

Relevant local refs:

- `transport/xhttp/xhttp.go:101`
- `transport/xhttp/xhttp.go:104`
- `transport/xhttp/xhttp.go:832`

Current state:

- validation rejects nested download-side `extra`
- downstream split-path support exists in limited form
- but nested reuse / xmux-style tuning still cannot flow through

Impact:

- current download-side transport surface is only partially wired
- parity with newer upstream config structures remains incomplete

#### 5. `xmux/reuse-settings` surface is incomplete

Priority: medium

Relevant local refs:

- `transport/xhttp/xhttp.go:185`
- `transport/xhttp/xhttp.go:432`
- `transport/xhttp/xhttp.go:1122`

Current state:

- existing xmux options cover only the older subset
- newer knobs such as `hKeepAlivePeriod` are missing

Impact:

- reduces keepalive tuning flexibility
- leaves local xhttp less capable than latest mihomo on long-lived transport
  behavior control

### Open questions

- This round compared against mihomo stable `v1.19.24`; it did not audit mihomo
  unreleased `main`.
- No confirmed local H3 `PacketConn` leak was reproduced in this round.
  Mihomo recently fixed one on their side, so outbound should eventually gain a
  targeted regression check for close-path correctness.

### Validation completed

Environment notes:

- host default Go toolchain was too old for this repo
- default `proxy.golang.org` download path timed out in this environment

Successful local verification:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./transport/xhttp
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./dialer/v2ray
```

Result:

- `./transport/xhttp`: pass
- `./dialer/v2ray`: pass

Interpretation:

- current branch is not failing basic local tests
- this round's findings are primarily optimization / parity / behavior-alignment
  issues, not an already reproduced functional regression

## Recommended next steps

Suggested execution order:

1. rework `packet-up` batching so `scMinPostsIntervalMs` behaves like a real
   timer-driven merge window
2. add true `http/1.1` xhttp mode support, or reject it explicitly instead of
   silently falling into H2-only machinery
3. add a default request-header profile closer to normal browser `fetch`
4. allow download-side nested `extra` / reuse settings to pass validation and
   reach transport wiring
5. expand xmux / reuse-settings coverage, starting with `hKeepAlivePeriod`

## Status

Current phase:

- [x] initial outbound/xhttp audit completed
- [x] latest stable mihomo comparison completed
- [x] local xhttp and v2ray tests revalidated
- [x] implementation plan selection
- [x] optimization changes
- [x] post-change regression validation

## 2026-05-03 Optimization execution ledger

Execution branch:

- outbound branch: `optimization`
- branch base: `personal/stable`
- branch point:
  - `3535c49` `fix(vision): return error for unsupported tls conn`

Integration validation baseline:

- dae repo: `/root/project/dae`
- dae branch used for validation: `bpf0.21.0`
- dae working tree note at start of this round:
  - user already has local modification in `DNS_OPTIMIZATION_MEMO.md`
  - outbound optimization work should not overwrite that file

Validation strategy for this round:

1. keep outbound code changes isolated on `optimization`
2. validate each fix locally in outbound first with targeted unit tests
3. use `dae/bpf0.21.0` as the integration lens by creating a temporary local
   modfile that replaces `github.com/daeuniverse/outbound` with `../outbound`
4. prefer targeted dae package tests / integration tests over broad repo churn
   while the branch still contains unrelated user memo edits
5. record both successful checks and unreproduced items explicitly instead of
   claiming blanket parity

Initial execution order selected for implementation:

1. fix high-confidence dial-chain / TLS-parameter propagation regressions
2. fix concrete connection-lifecycle bugs with clear close-path or map-lookup
   correctness issues
3. tighten route-aware cache scoping and caller-context propagation for pooled
   transports
4. revisit larger Hysteria2 route-awareness issues after the first regression
   batch is green

Stable reference re-check for the xhttp lane:

- the original audit targeted mihomo stable `v1.19.24`
- a later intermediate check in this worklog briefly treated `v1.19.23` as the
  latest stable baseline
- user requested a re-check against `v1.19.24`
- rechecked on `2026-05-03`:
  - latest stable mihomo release is `v1.19.24`
  - release date: `2026-04-20T01:56:58Z`

Impact of the confirmed `v1.19.24` baseline:

- `http/1.1` support is in scope again and should no longer be treated as
  intentionally unsupported by stable
- `packet-up` merge behavior tied to `scMinPostsIntervalMs` is again a real
  stable-parity target
- `hKeepAlivePeriod` becomes part of the xmux/reuse-settings parity surface
- `downloadSettings.xhttpSettings.extra` remains relevant specifically for
  nested reuse/xmux settings

Implementation ledger:

- [x] `dialer/v2ray`: `http/h2` now uses the current dial chain instead of
      `direct.SymmetricDirect`
- [x] `protocol/http`: HTTPS proxy now preserves `allowInsecure` /
      `skipVerify` / `utlsImitate`
- [x] `protocol/http`: plain HTTP/1.1 underlay connections now close on
      `Conn.Close()`
- [x] `protocol/http`: H2 pool lookup bug fixed and reuse is now route-context
      aware per proxy instance
- [x] `transport/meek`: TLS config is now applied to requests, round-tripper
      reuse is route-aware, and requests honor caller contexts
- [x] `transport/grpc`: cache scoping now includes transport context, and
      stream setup now follows caller cancellation during establishment only
- [x] `protocol/hysteria2`: route context now reaches the UDP underlay, client
      reuse is separated by underlay route, and `udphop` no longer reuses the
      original cancelable dial context for later hops

Batch 1 additional compatibility fixes completed together with the items above:

- VLESS `allowInsecure` parsing now accepts aliases:
  - `allow_insecure`
  - `allowinsecure`
  - `skipVerify`
- VLESS meek export now preserves the actual `url=` field instead of exporting
  the wrong source field
- standalone HTTP proxy export now preserves `allowInsecure` even when `sni` is
  empty

### Batch 1 validation

Outbound targeted tests passed with:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./common ./dialer/http ./dialer/v2ray
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./protocol/http ./transport/meek ./transport/grpc
```

Result:

- all packages above: pass
- new regression coverage added for:
  - HTTPS proxy TLS parameter preservation
  - HTTP proxy export fidelity
  - VLESS alias parsing / meek export
  - H2 route-aware pool selection
  - meek route-aware round-tripper reuse
  - grpc cache key separation and detached establishment context

`dae/bpf0.21.0` integration validation was performed via a temporary local
modfile replacing `github.com/daeuniverse/outbound` with `../outbound`.

Preparation steps used:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
```

Successful `dae` checks:

```bash
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 \
  -run TestNewDirectDialerPrefersInjectedResolverDialer \
  ./component/outbound/dialer
```

```bash
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Integration interpretation:

- targeted `dae` outbound dialer test: pass
- compile-only validation for `dae` outbound dialer and control packages: pass
- a full `go test ./component/outbound/dialer` run did not complete within the
  interactive window, so this batch uses targeted test + compile gates instead
  of claiming full package green
- temporary `go.local.mod` / `go.local.sum` were removed after validation to
  avoid leaving extra repo noise in `dae`

### Batch 2 validation

Hysteria2 targeted checks passed with:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -run \
  'TestGetClientForRouteCachesByUnderlayNetwork|TestNewConnFactoryPreservesUnderlayNetwork' \
  ./protocol/hysteria2
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -run '^$' ./protocol/hysteria2/...
```

Follow-up `dae/bpf0.21.0` compile validation after the Hysteria2 batch:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- `./protocol/hysteria2`: targeted route-awareness tests pass
- `./protocol/hysteria2/...`: compile pass
- `dae ./component/outbound/dialer ./control`: compile pass against local
  `../outbound`

### Batch 3 implementation notes

This batch returned to the original xhttp audit and prioritized the remaining
items using the then-current local stable assumption.

Completed in this batch:

- [x] `transport/xhttp`: align default request headers with current stable
      browser-like defaults:
  - `User-Agent: Mozilla/5.0`
  - `Accept: */*`
  - `Accept-Language: en-US,en;q=0.9`
  - `Cache-Control: no-cache`
  - `Pragma: no-cache`
- [x] `transport/xhttp`: allow
      `downloadSettings.xhttpSettings.extra` for nested `xmux` only, and wire
      it into download-side reuse selection
- [x] `transport/xhttp`: make H2 request-client/open-conn path preserve caller
      `MagicNetwork`
- [x] `transport/xhttp`: make H2 packet-up xmux reuse keys route-aware by
      including the caller network context
- [x] `transport/xhttp`: preserve `mptcp` as well as mark when H3 builds its
      UDP underlay network

Related hardening completed while touching adjacent paths:

- `transport/grpc`: detached establishment context handling was tightened so
  `stopFollowing()` wins over late parent-cancel races
- `protocol/hysteria2`: underlay packet-conn assertions now fail with ordinary
  errors instead of type-assumption crashes when a bad/nil underlay is returned

### Batch 3 validation

Outbound xhttp validation passed with:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./transport/xhttp
```

Broader outbound regression subset passed with:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 \
  ./common ./dialer/http ./dialer/v2ray ./protocol/http \
  ./transport/meek ./transport/grpc ./transport/xhttp
```

Hysteria2 follow-up validation for this batch remained targeted:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -run \
  'TestGetClientForRouteCachesByUnderlayNetwork|TestNewConnFactoryPreservesUnderlayNetwork' \
  ./protocol/hysteria2
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -run '^$' ./protocol/hysteria2/...
```

`dae/bpf0.21.0` integration checks for this batch:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- `outbound ./transport/xhttp`: pass
- broader outbound regression subset above: pass
- `dae ./component/outbound/dialer ./control` compile gate against local
  `../outbound`: pass
- `dae` `TestNewFromLinkXHTTPH3Auto` was attempted but did not complete in the
  interactive window, so this batch records compile integration rather than
  claiming that heavier integration test as green

### Batch 4 implementation notes

This batch rechecked mihomo stable against the confirmed `v1.19.24` release and
continued the xhttp lane accordingly.

Completed in this batch:

- [x] `transport/xhttp`: add a real exact-`http/1.1` request-client path
      instead of rejecting that stable mode
- [x] `transport/xhttp`: move `packet-up` batching closer to `v1.19.24`
      semantics by using `scMinPostsIntervalMs` as the merge window instead of
      a fixed pre-flush delay plus post-send sleep
- [x] `transport/xhttp`: parse xmux `hKeepAlivePeriod`
- [x] `transport/xhttp`: apply `hKeepAlivePeriod` to H2/H3 client setup
      where the local transport surface allows it
- [x] `transport/xhttp`: harden request preparation so nil cloned headers no
      longer panic on padding/meta application

Additional validation coverage added in this batch:

- exact `http/1.1` mode smoke coverage at request-client level
- `packet-up` merge-window coverage for two writes coalescing into one request
- xmux `hKeepAlivePeriod` parsing coverage

### Batch 4 validation

Confirmed xhttp `v1.19.24` follow-up checks passed with:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./transport/xhttp
```

Broader outbound regression subset revalidated with:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 \
  ./common ./dialer/http ./dialer/v2ray ./protocol/http \
  ./transport/meek ./transport/grpc ./transport/xhttp
```

Hysteria2 remained on targeted+compile gates in this batch:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -run \
  'TestGetClientForRouteCachesByUnderlayNetwork|TestNewConnFactoryPreservesUnderlayNetwork' \
  ./protocol/hysteria2
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -run '^$' ./protocol/hysteria2/...
```

`dae/bpf0.21.0` local integration gate for this batch:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- `./transport/xhttp`: pass
- broader outbound regression subset above: pass
- `./protocol/hysteria2`: targeted route-awareness checks pass
- `./protocol/hysteria2/...`: compile pass
- `dae ./component/outbound/dialer ./control`: compile pass against local
  `../outbound`
- temporary `go.local.mod` / `go.local.sum` were removed again after validation

### Batch 5 implementation notes

This batch kept following `v1.19.24` xhttp parity, focused on download-side
request overrides and one remaining field-alias mismatch.

Completed in this batch:

- [x] `transport/xhttp`: accept `extra.uplinkHttpMethod` as an alias of
      `uplinkHTTPMethod`
- [x] `transport/xhttp`: support download-side request header overrides from
      `downloadSettings.xhttpSettings.headers`
- [x] `transport/xhttp`: support download-side padding overrides from
      `downloadSettings.xhttpSettings`:
  - `xPaddingBytes`
  - `xPaddingObfsMode`
  - `xPaddingKey`
  - `xPaddingHeader`
  - `xPaddingPlacement`
  - `xPaddingMethod`
- [x] `transport/xhttp`: support download-side session metadata overrides from
      `downloadSettings.xhttpSettings`:
  - `sessionPlacement`
  - `sessionKey`
- [x] `transport/xhttp`: make actual download GET requests use the download-side
      request profile instead of always inheriting the upload-side headers

Validation added in this batch:

- alias parsing coverage for `uplinkHttpMethod`
- unit coverage for download-side request-profile overrides
- broader regression subset re-run after the new download-side request changes

### Batch 5 validation

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./transport/xhttp
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 \
  ./common ./dialer/http ./dialer/v2ray ./protocol/http \
  ./transport/meek ./transport/grpc ./transport/xhttp
```

`dae/bpf0.21.0` compile gate revalidated with local `../outbound` replace:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- `./transport/xhttp`: pass
- broader outbound regression subset above: pass
- `dae ./component/outbound/dialer ./control`: compile pass against local
  `../outbound`

### Batch 6 implementation notes

This batch moved one of the broader engineering cleanup items forward:
reducing package-global direct-dialer initialization coupling.

Completed in this batch:

- [x] `protocol/direct`: add lazy initialization for
  `SymmetricDirect` / `FullconeDirect`
- [x] `protocol/direct`: initialize default direct dialers on package load so
  standalone consumers and tests no longer start from nil globals by default
- [x] `dialer/direct`: stop returning raw globals directly; use the lazy getter
  path instead
- [x] add unit coverage proving direct getters recover from nil globals

Validation for this batch:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./protocol/direct ./dialer
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -run '^$' \
  ./protocol/hysteria2 ./protocol/tuic ./protocol/juicity \
  ./protocol/shadowsocks_stream ./transport/shadowsocksr
```

`dae/bpf0.21.0` compile gate revalidated after the direct-layer change:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- `./protocol/direct`: pass
- `./dialer`: compile pass
- related protocol packages above: compile pass
- `dae ./component/outbound/dialer ./control`: compile pass against local
  `../outbound`
- temporary `go.local.mod` / `go.local.sum` were removed again after validation

### Batch 7 implementation notes

This batch converted several protocol tests from implicit live-network
dependencies into explicit live integration tests so the default local test
baseline is stable.

Completed in this batch:

- [x] add shared live-test helper gated by `OUTBOUND_LIVE_TEST=1`
- [x] gate live Hysteria2 tests behind the explicit helper
- [x] gate live TUIC tests behind the explicit helper
- [x] gate live Juicity tests behind the explicit helper
- [x] gate live Shadowsocks stream tests behind the explicit helper
- [x] gate live ShadowsocksR tests behind the explicit helper

Why this matters:

- these tests previously depended on real remote servers such as:
  - `localhost:8443`
  - `example.com:10383`
  - `example.com:50001`
  - `127.0.0.1:8989`
  - public sites / DNS targets such as `ipinfo.io` and `www.baidu.com`
- the prior default `go test` outcome therefore mixed product correctness with
  whether the developer happened to have matching live infrastructure
- after this change, default package tests are deterministic while still
  preserving an explicit live path when needed

Default validation after this change:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 \
  ./protocol/direct ./protocol/hysteria2 ./protocol/tuic ./protocol/juicity \
  ./protocol/shadowsocks_stream ./transport/shadowsocksr \
  ./transport/xhttp ./protocol/http ./transport/meek ./transport/grpc \
  ./dialer/http ./dialer/v2ray
```

Live opt-in rule now used for the gated tests:

```bash
OUTBOUND_LIVE_TEST=1 go test ./protocol/hysteria2 ./protocol/tuic \
  ./protocol/juicity ./protocol/shadowsocks_stream ./transport/shadowsocksr
```

`dae/bpf0.21.0` compile gate revalidated after the test-shape changes:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- default local regression subset above: pass
- live protocol tests are now explicit opt-in instead of accidental default
  failures
- `dae ./component/outbound/dialer ./control`: compile pass against local
  `../outbound`
- temporary `go.local.mod` / `go.local.sum` were removed again after validation

### Batch 8 implementation notes

This batch addressed another recorded structural risk:
the legacy `vmess+tls+grpc` path previously wrapped grpc by pointing the grpc
dialer back at the same `vmess.Dialer`, which made the transport layering
recursively self-referential.

Completed in this batch:

- [x] `protocol/vmess`: stop mutating the dialer into a self-referential grpc
      wrapper during `DialContext`
- [x] `protocol/vmess`: build grpc transport wrapping from the parent dialer
      only
- [x] add targeted unit coverage proving:
  - grpc wrapping uses the parent dialer
  - grpc wrapping does not recurse back into the same vmess dialer
  - plain vmess keeps the original parent dialer unchanged

Validation for this batch:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 ./protocol/vmess
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 \
  ./protocol/direct ./protocol/vmess ./protocol/hysteria2 ./protocol/tuic \
  ./protocol/juicity ./protocol/shadowsocks_stream ./transport/shadowsocksr \
  ./transport/xhttp ./protocol/http ./transport/meek ./transport/grpc \
  ./dialer/http ./dialer/v2ray
```

`dae/bpf0.21.0` compile gate revalidated after the vmess transport-layer change:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- `./protocol/vmess`: pass
- broader outbound regression subset above: pass
- `dae ./component/outbound/dialer ./control`: compile pass against local
  `../outbound`
- temporary `go.local.mod` / `go.local.sum` were removed again after validation

### Batch 9 validation milestone

After the direct-layer fallback work, the live-test gating cleanup, the vmess
grpc recursion fix, and the earlier xhttp/proxy/route-awareness changes, the
repository-level local test baseline improved enough to recheck the full
outbound suite.

Successful full-suite validation:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -timeout 60s ./...
```

Result:

- `outbound go test ./...`: pass

Follow-up `dae/bpf0.21.0` compile gate after the full-suite pass:

```bash
cp go.mod go.local.mod
/usr/lib/go-1.23/bin/go mod edit -modfile=go.local.mod \
  -replace github.com/daeuniverse/outbound=../outbound
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go mod tidy -modfile=go.local.mod
GOTOOLCHAIN=go1.24.3 \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
/usr/lib/go-1.23/bin/go test -modfile=go.local.mod -count=1 -run '^$' \
  ./component/outbound/dialer ./control
```

Result:

- `dae ./component/outbound/dialer ./control`: compile pass against local
  `../outbound`
- temporary `go.local.mod` / `go.local.sum` were removed again after validation

### Batch 10 implementation notes

This batch continued improving the test surface for packages that still showed
`[no test files]` but were simple enough to cover with stable unit tests.

Completed in this batch:

- [x] add unit coverage for `transport/tls` config parsing:
  - insecure aliases
  - ALPN propagation
  - option-driven `utls` override
- [x] add unit coverage for `transport/ws` config parsing:
  - host-header override
  - `wss` TLS settings
  - ALPN propagation
- [x] add unit coverage for `transport/httpupgrade` config parsing:
  - path normalization
  - TLS settings
  - explicit `serverName`
- [x] add unit coverage for `protocol/socks5` address encode/decode helpers
- [x] add unit coverage for `transport/simpleobfs` config parsing
- [x] add unit coverage for `protocol/anytls` dialer construction
- [x] add unit coverage for `transport/mux` TCP wrapping and UDP passthrough

Resulting effect on test surface:

- these packages no longer report `[no test files]`:
  - `transport/tls`
  - `transport/ws`
  - `transport/httpupgrade`
  - `protocol/socks5`
  - `transport/simpleobfs`
  - `protocol/anytls`
  - `transport/mux`

Validation for this batch:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 \
  ./protocol/anytls ./protocol/socks5 \
  ./transport/httpupgrade ./transport/mux \
  ./transport/simpleobfs ./transport/tls ./transport/ws
```

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test -count=1 -timeout 60s ./...
```

Result:

- targeted new package tests above: pass
- `outbound go test ./...`: still pass after the added coverage

## 2026-05-03 Audit: non-xhttp outbound review

This round explicitly excludes `transport/xhttp`.

Primary local review scope:

- `dialer/v2ray/v2ray.go`
- `protocol/http/http.go`
- `protocol/hysteria2/*`
- `protocol/anytls/*`
- `protocol/tuic/*`
- `protocol/juicity/*`
- `transport/grpc/grpc_client.go`

### Findings

#### 1. V2Ray `http/h2` transport bypasses the current dial chain

Priority: high

Relevant refs:

- `dialer/v2ray/v2ray.go:213`
- `dialer/v2ray/v2ray.go:236`

Current state:

- `ws`, `grpc`, `meek`, `httpupgrade`, `xhttp` all wrap the current `d`
- `http/http2/h2` instead hardcodes `direct.SymmetricDirect`

Impact:

- chained dialers can be bypassed unexpectedly
- route mark / mptcp / upstream chaining semantics can be lost specifically on
  the V2Ray `http/h2` transport path

#### 2. HTTPS HTTP proxy path drops `allowInsecure` / `skipVerify` /
`utlsImitate`

Priority: high

Relevant refs:

- `protocol/http/http.go:43`
- `protocol/http/http.go:58`
- `protocol/http/http.go:65`
- `protocol/http/http.go:79`

Current state:

- the code builds a synthetic URL containing only `sni` and `alpn`
- after that, it reads `allowInsecure`, `skipVerify`, and `utlsImitate` from
  the synthetic URL instead of the original input URL

Impact:

- HTTPS proxy links can silently ignore certificate-bypass flags
- `utlsImitate` can be lost
- behavior diverges from what the parsed link appears to request

#### 3. Hysteria2 currently drops route mark / mptcp information on underlay
dials

Priority: medium-high

Relevant refs:

- `protocol/hysteria2/dialer.go:69`
- `protocol/hysteria2/dialer.go:87`
- `protocol/hysteria2/dialer.go:129`
- `protocol/hysteria2/client/client.go:48`
- `protocol/hysteria2/client/client.go:61`

Current state:

- `DialContext` parses `magicNetwork`, but the client underlay is created from
  plain `"udp"` dials
- the Hysteria2 client already carries an inline TODO about handling different
  marks for the same dialer

Impact:

- policy-routing expectations can be silently ignored
- one dialer instance cannot safely represent multiple route marks / mptcp
  combinations

#### 4. Several long-lived connection pools are not route-aware after warmup

Priority: medium-high

Relevant refs:

- `protocol/anytls/dialer.go:78`
- `protocol/anytls/dialer.go:98`
- `protocol/tuic/client.go:51`
- `protocol/juicity/client.go:92`

Current state:

- AnyTLS reuses any idle session without checking the requested `tcpNetwork`
- TUIC / Juicity return an existing QUIC connection immediately when one is
  already cached, without checking whether the current dial request uses a
  different route mark / dialer path

Impact:

- once a session is warm, later requests can ride the wrong underlay
- mixed-policy traffic is at risk of being pinned to the first established path

#### 5. gRPC transport cache scoping is too coarse, and stream creation ignores
caller context

Priority: medium

Relevant refs:

- `transport/grpc/grpc_client.go:328`
- `transport/grpc/grpc_client.go:340`
- `transport/grpc/grpc_client.go:372`
- `transport/grpc/grpc_client.go:416`

Current state:

- global client-conn cache is keyed only by `address`
- cache lookup ignores:
  - `serverName`
  - `allowInsecure`
  - `mark`
  - `mptcp`
  - effective chain dialer identity
- `TunCustomName` is opened with `context.Background()` instead of the caller's
  `ctx`

Impact:

- wrong connection reuse is possible across distinct transport contexts
- `DialContext` deadline / cancellation semantics are weakened during stream
  establishment

### Validation completed

Full local test sweep attempted with:

```bash
PATH=/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.3.linux-amd64/bin:$PATH \
GOPROXY=https://goproxy.cn,direct \
GOSUMDB=sum.golang.google.cn \
go test ./...
```

Result:

- many packages passed
- the full suite is currently not green

Observed package failures:

- `protocol/direct`
- `protocol/hysteria2`
- `protocol/juicity`
- `protocol/shadowsocks_stream`
- `protocol/tuic`
- `transport/shadowsocksr`

Observed failure pattern:

- failures were panics, not ordinary assertion mismatches
- several tests depend on `direct.SymmetricDirect`, but repo-wide test bootstrap
  does not currently initialize the direct dialer globals before those tests run

Interpretation:

- there are real non-xhttp audit findings in transport / routing behavior
- independently of those findings, the current repo-wide test baseline should be
  cleaned up before relying on `go test ./...` as a CI gate

## 2026-05-03 Audit: all protocols with dae-core integration lens

This round broadens the review to all protocol families and checks them against
how `dae` actually integrates outbound:

- `dae/component/outbound/dialer/register.go`
- `dae/component/outbound/dialer/dialer.go`
- `dae/component/outbound/dialer/connectivity_check.go`
- `dae/component/dns/upstream.go`
- `dae/engine/runtime.go`

Integration assumptions confirmed from local code:

- `dae` builds outbound nodes through `NewNetproxyDialerFromLink(...)`
- route mark / mptcp information is carried through `netproxy.MagicNetwork`
- health checks and DNS bootstrap use injected resolver dialers instead of
  relying on outbound's package globals
- this makes route-awareness, context propagation, and link-parse fidelity
  materially important

### Additional findings

#### 1. HTTP proxy transport never closes plain HTTP/1.1 underlay connections

Priority: high

Relevant refs:

- `protocol/http/conn.go:303`
- `protocol/http/conn.go:326`

Current state:

- `Conn.Close()` is a no-op for the outer proxy connection wrapper
- only the H2 stream wrapper closes its request/response bodies

Impact under dae-core:

- nodes using HTTP proxy transport or V2Ray `http/h2` fallback-to-HTTP/1.1
  behavior can leak tunnels
- repeated probe / traffic lifecycles can accumulate stale underlay connections

#### 2. Meek transport builds TLS settings but does not actually use them

Priority: high

Relevant refs:

- `transport/meek/dialer.go:63`
- `transport/meek/dialer.go:79`
- `transport/meek/httprt.go:22`
- `transport/meek/httprt.go:85`

Current state:

- `NewDialer()` constructs `m.tlsConfig`
- `DialContext()` creates `httpTripperClient` without assigning that
  `tlsConfig`
- cached HTTP transports therefore run with nil TLS client config

Impact:

- `allowInsecure`
- ALPN
- SNI expectations

may all be silently ignored on meek links.

#### 3. Meek session / request lifecycle ignores caller context and cache scope

Priority: medium-high

Relevant refs:

- `transport/meek/dialer.go:96`
- `transport/meek/client.go:26`
- `transport/meek/httprt.go:17`
- `transport/meek/httprt.go:47`

Current state:

- session creation uses `context.Background()` instead of the caller's `ctx`
- HTTP requests are created with `http.NewRequest(...)` rather than
  `http.NewRequestWithContext(...)`
- round-tripper cache is global and keyed too coarsely for mixed dialer
  contexts

Impact under dae-core:

- health-check cancellation / timeout semantics are weakened
- different route contexts can accidentally share the same cached transport

#### 4. HTTP/2 proxy pool has a concrete map lookup bug and also mixes route
contexts by address

Priority: medium-high

Relevant refs:

- `protocol/http/conn.go:357`
- `protocol/http/conn.go:449`
- `protocol/http/conn.go:457`
- `protocol/http/conn.go:462`

Current state:

- `GetClientConn()` loads `addr2Dialer` twice
- the second lookup should have been `addr2Somark`
- pool state is keyed by `addr` only, while dialer identity and magic-network
  state are stored per address and can be overwritten

Impact:

- repeated H2 reuse can attach to the wrong route context
- the current implementation also has a direct correctness bug in the lookup
  path

#### 5. V2Ray link parse / export fidelity is inconsistent for real-world
subscription traffic

Priority: medium

Relevant refs:

- `dialer/v2ray/v2ray.go:361`
- `dialer/v2ray/v2ray.go:375`
- `dialer/v2ray/v2ray.go:497`
- `dialer/http/http.go:99`

Current state:

- `ParseVlessURL()` only recognizes exact `allowInsecure`, not aliases such as
  `allow_insecure`, `allowinsecure`, or `skipVerify`
- VLESS `meek` export writes `url` from `s.Host` instead of the parsed meek URL
  field held in `s.Path`
- standalone HTTP proxy export only persists `allowInsecure` when `s.SNI` is
  non-empty

Impact under dae-core:

- imported subscription nodes can lose intended TLS verification behavior
- save / reload or export flows can silently mutate node semantics

### Protocol areas that looked structurally acceptable in this pass

No new high-confidence route or lifecycle issues were identified in the basic
TCP/UDP wrappers for:

- `protocol/vless`
- `protocol/trojanc`
- `protocol/shadowsocks`
- `protocol/shadowsocks_2022`
- `protocol/socks5`

Reason:

- these paths generally parse `magicNetwork`
- preserve `mark` / `mptcp` when promoting to the real underlay transport
- do not introduce broad global connection caches comparable to meek / grpc /
  h2 / quic-based pooled clients

## 2026-05-03 Focus audit: Hysteria2

### Findings

#### 1. Underlay dials ignore `magicNetwork` route context

Priority: high

Relevant refs:

- `protocol/hysteria2/dialer.go:73`
- `protocol/hysteria2/dialer.go:89`
- `protocol/hysteria2/dialer.go:129`

Current state:

- `DialContext()` parses `magicNetwork`
- but the real QUIC underlay is always created from plain `"udp"` dials

Impact under dae-core:

- route mark / mptcp policy can be lost
- behavior diverges from protocols that preserve `MagicNetwork` into their
  underlay transport

#### 2. The client caches one QUIC connection without route-aware separation

Priority: high

Relevant refs:

- `protocol/hysteria2/client/client.go:48`
- `protocol/hysteria2/client/client.go:61`
- `protocol/hysteria2/client/client.go:165`
- `protocol/hysteria2/client/client.go:216`

Current state:

- the client explicitly carries a TODO about different marks on one dialer
- after the first successful connect, later TCP / UDP requests reuse the same
  cached QUIC connection

Impact:

- mixed-route traffic can be pinned to the first successful underlay
- this is especially risky in dae-core because one dialer instance participates
  in probe, runtime, and policy-routed traffic

#### 3. `udphop` captures the original dial context and reuses it for future
hops

Priority: medium-high

Relevant refs:

- `protocol/hysteria2/dialer.go:71`
- `protocol/hysteria2/dialer.go:72`
- `protocol/hysteria2/udphop/conn.go:109`
- `protocol/hysteria2/udphop/conn.go:129`

Current state:

- the `dialFunc` closure used by `udphop` captures the initial `ctx`
- hop loop later keeps using that same closure for future port hops

Impact:

- if the original dial context has already timed out or been canceled, later
  hop attempts can fail systematically
- this weakens the correctness of the port-hopping path over long-lived
  sessions

#### 4. UDP deadline handling closes the whole session and is not
direction-specific

Priority: medium

Relevant refs:

- `protocol/hysteria2/client/udp.go:105`
- `protocol/hysteria2/client/udp.go:122`
- `protocol/hysteria2/client/udp.go:127`

Current state:

- `SetReadDeadline()` and `SetWriteDeadline()` both forward to `SetDeadline()`
- deadline expiry closes the entire UDP session
- source already carries `FIXME: Single direction`

Impact:

- deadline semantics are rougher than callers usually expect
- this can create surprising behavior if higher layers rely on read/write
  deadlines independently

### Validation note

`go test ./...` currently reports a `protocol/hysteria2` panic, but that
specific failure is primarily test-harness related:

- `protocol/hysteria2/dialer_test.go` depends on `direct.SymmetricDirect`
- repo-wide tests do not initialize the direct dialer globals before that test
  runs

So the current Hysteria2 findings above are code-review findings, not merely a
restatement of that panic.

## 2026-05-03 Additional engineering optimization opportunities

These are broader cleanup opportunities beyond the protocol-specific findings
above.

### 1. Remove package-global direct dialer dependency from outbound core paths

Priority: medium

Relevant refs:

- `dialer/direct.go:8`
- `protocol/direct/dialer.go:19`

Current state:

- outbound's `NewDirectDialer()` returns package globals only
- those globals must be initialized elsewhere before safe use
- dae-core already works around this by injecting resolver dialers or building
  fallback direct dialers on its side

Why this is worth optimizing:

- standalone outbound consumers and tests still inherit hidden initialization
  coupling
- repo-wide test panics already show this friction

### 2. Legacy `vmess+tls+grpc` path looks structurally unsafe

Priority: medium

Relevant refs:

- `protocol/vmess/dialer.go:100`
- `protocol/vmess/dialer.go:112`

Current state:

- when `ProtocolVMessTlsGrpc` is selected, `DialContext()` mutates
  `d.nextDialer`
- the injected grpc dialer points `NextDialer` back to the same `vmess.Dialer`

Assessment:

- if this path is still intended to be reachable, it deserves a dedicated
  verification pass or explicit removal
- the current shape is difficult to reason about and appears prone to
  self-recursive behavior

### 3. TLS / insecure / alias parsing is duplicated too widely

Priority: medium

Relevant refs:

- `protocol/http/http.go:65`
- `transport/ws/ws.go:76`
- `transport/tls/tls.go:62`
- `dialer/tuic/tuic.go:89`
- `dialer/trojan/trojan.go:139`
- `dialer/juicity/juicity.go:99`
- `dialer/http/http.go:57`

Current state:

- many packages manually parse the same boolean aliases:
  - `allowInsecure`
  - `allow_insecure`
  - `allowinsecure`
  - `skipVerify`

Why this is worth optimizing:

- behavior drift is already visible across protocols
- one shared helper would reduce both code volume and compatibility bugs

### 4. Context ownership is inconsistent across long-lived transports

Priority: medium

Relevant refs:

- `transport/meek/dialer.go:96`
- `protocol/juicity/dialer.go:148`
- `protocol/hysteria2/client/client.go:354`
- `protocol/tuic/client.go:175`

Current state:

- several long-lived flows still use `context.Background()` or `context.TODO()`
  in places where caller-owned lifetime would be safer

Why this is worth optimizing:

- makes cancellation, shutdown, and probe isolation harder to reason about
- increases the chance of hidden hangs or unexpectedly long-lived background
  activity

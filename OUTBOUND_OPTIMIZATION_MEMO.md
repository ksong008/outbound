# Outbound Optimization Memo

Branch: personal/stable
Repo: /Users/Shaka/New project/outbound

## Scope

This memo records the recent outbound-side protocol and transport work carried out in the current cycle.

Main areas covered so far:

- VLESS over TLS compatibility improvements
- XTLS / VLESS troubleshooting conclusions
- XHTTP support investigation and first implementation phase

## 1. VLESS version support attempt

Initial attempt:
- `855d19b` `Add configurable VLESS version support`

Outcome:
- intentionally rolled back
- final remote branch was reset so this feature is **not** part of `origin/personal/stable`

Reason:
- the original user goal was not general VLESS versioning
- the real requirement turned out to be compatibility around `flow=xtls-rprx-vision`

Cleanup result:
- remote `personal/stable` was reset back to:
  - `1456668` `Add outbound quicpersonal workflow`

Conclusion:
- VLESS version support is not active in the current stable branch
- if revisited later, it should be treated as a separate feature line

## 2. XTLS / VLESS compatibility investigation

Finding:
- `xtls-rprx-vision` itself was already recognized by outbound
- the actual runtime issue observed during troubleshooting was **not** caused by missing flow support

Verified:
- raw links containing:
  - `flow=xtls-rprx-vision`
  - `fp=chrome`
  - `alpn=h2,http/1.1`
  were successfully tested directly against the target server

Important conclusion:
- for the reported failing subscription case, the root cause was eventually narrowed down to the source link formatting rather than outbound vision support itself
- specifically, a missing explicit `type=tcp` in the subscription source was enough to break the node

Operational takeaway:
- `VLESS + security=tls + flow=xtls-rprx-vision` should be treated as requiring an explicit transport type in exported links

## 3. VLESS TLS fingerprint and ALPN handling

Commit already pushed to remote:
- `7761cda` `Honor VLESS TLS fingerprint and ALPN hints`

Problem:
- on the `VLESS + type=tcp + security=tls` path, `fp` and `alpn` were parsed from links but not fully honored by the TLS dial path

Changes:
- `fp` now maps into `utlsImitate` for `security=tls`
- `alpn` is now forwarded into the TLS dial configuration

Files:
- `dialer/v2ray/v2ray.go`
- tests in:
  - `dialer/v2ray/v2ray_test.go`
  - `protocol/vless/dialer_test.go`

Validation:
- local tests for `./protocol/vless` and `./dialer/v2ray` passed at the time of the change

Importance:
- this was not the primary fix for the reported subscription issue
- but it improves compatibility with real-world VLESS TLS links that include TLS fingerprint and ALPN hints

## 4. XHTTP support investigation

Problem found:
- `daed` and `dae-node-parser` already expose and parse `type=xhttp`
- outbound previously did **not** support `xhttp` at runtime
- calling VLESS with `type=xhttp` failed with:
  - `unexpected field: network: xhttp`

Confirmed by:
- direct local runtime test against outbound's `V2Ray.Dialer`

Relevant findings:
- `ParseVlessURL()` could parse `type=xhttp`
- `ExportToURL()` did not preserve all xhttp-specific fields
- runtime switch in `dialer/v2ray/v2ray.go` had no `case "xhttp"`
- there was no `transport/xhttp`

## 5. XHTTP support phase 1 (local working tree, not yet committed)

Current local working tree changes:
- `dialer/v2ray/v2ray.go`
- `dialer/v2ray/v2ray_test.go`
- `transport/xhttp/xhttp.go`

Phase 1 goals:
- add xhttp-specific fields to the `V2Ray` model:
  - `XHTTPMode`
  - `XHTTPExtra`
- make `ParseVlessURL()` and `ExportToURL()` preserve:
  - `type=xhttp`
  - `mode`
  - `extra`
- add `case "xhttp"` to the V2Ray dialer path
- provide an initial real runtime path for:
  - `tls + auto`
  - `tls + stream-up`
  - `tls + stream-one`
  - `tls + packet-up`

Current status:
- local unit tests passed:
  - `go test ./dialer/v2ray`
  - `go test ./transport/xhttp`
- direct local runtime check no longer fails with:
  - `unexpected field: network: xhttp`
- the xhttp link now enters the dialer path successfully
- `auto` now resolves to `stream-up` when `tls` is enabled
- `transport/xhttp` now creates:
  - a real HTTP/2 session
  - a download `GET`
  - an upload `POST`
  - a shared per-session path for upstream/downstream traffic
- `stream-one` is now supported as a single `POST` session where the response body serves downstream traffic
- `packet-up` is now supported as a per-write `POST` upload model with a persistent download `GET`
- `extra` is no longer pure passthrough only:
  - request headers can now be applied from JSON
  - `noGRPCHeader` can suppress the default gRPC-style content type
- `extra.downloadSettings` now has limited support:
  - downstream can be split to a separate `xhttp + tls` endpoint
  - this is currently a constrained subset, not full Xray parity

Important limitation:
- this is still **not** full Xray-compatible xhttp support
- current phase 1 establishes:
  - field preservation
  - dialer entrypoint support
  - `tls + auto/stream-up/stream-one/packet-up` MVP semantics
- it does **not** yet fully implement:
  - full `downloadSettings` parity
  - H3 / QUIC mode
  - advanced `extra` semantics beyond basic headers / `noGRPCHeader`
  - XMUX-related behavior

## 6. Recommended next steps

If xhttp work continues, the recommended order is:

1. commit current phase 1 work as a clearly labeled MVP
2. define the intended compatibility target against Xray xhttp semantics
3. evolve `transport/xhttp` from MVP `stream-up` behavior toward broader Xray compatibility
4. add mode-specific tests for:
   - `auto`
   - `stream-up`
   - `stream-one`
5. only then evaluate:
   - H3
   - packet mode
   - `downloadSettings`
   - `extra` JSON semantics

## Current summary

At the time of this memo:

- `origin/personal/stable` includes:
  - `7761cda` VLESS TLS fingerprint / ALPN support
- `origin/personal/stable` does **not** include:
  - VLESS version support
- local working tree currently contains uncommitted phase 1 xhttp support work

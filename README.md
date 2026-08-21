# portmirror

A lightweight HTTP capture agent for Windows and IIS. It shows you the requests and responses
flowing through a server without a proxy, without a desktop GUI, and **without recycling the
application pool**.

**[nihirdas.github.io/portmirror](https://nihirdas.github.io/portmirror/)** — the idea, the roadmap, and where to help.

> Status: early. Today's build captures inbound request metadata. Bodies and response
> overriding are on the roadmap below.

## Why

**Two reasons, and the first one has a date on it.**

On 3 August 2026 Progress Telerik announced that [Fiddler Classic is licensed for non-commercial
use only](https://www.telerik.com/fiddler/fiddler-classic/commercial-use), effective **17 September
2026**. Personal, educational and individual learning use is still fine; commercial, business,
organisational or revenue-generating use requires [Fiddler
Everywhere](https://www.telerik.com/purchase/fiddler), a per-user subscription. Fiddler Classic
itself "is not in active development and offers no commitments for releases, patches, or technical
support" — [Telerik's
documentation](https://www.telerik.com/fiddler/fiddler-classic/documentation/introduction).

That is a fair way to run a business, and Fiddler Everywhere is a capable product. But the thing
that went away was not a feature set — it was a small free local tool you could put on a test
machine without asking anyone. Portmirror is not trying to replace Fiddler Everywhere; it is trying
to be the small thing that got taken away.

*(Licensing and pricing change. The links above are authoritative; this file is not. Checked August
2026.)*

The second reason is structural and has nothing to do with licensing: a proxy captures by making
itself the machine's proxy. A .NET worker process resolves its proxy **once, at startup**, and
WinINet proxy settings are per-user — so a `w3wp.exe` that was already running never routes
through it. That is why "just run Fiddler on the box" so often ends in *recycle the app pool
and try again*, which throws away the very state you were trying to observe.

No proxy can fix that. So portmirror is not a proxy.

It reads the HTTP.SYS ETW provider instead — the kernel driver every IIS request already passes
through. Capture starts and stops underneath a running application, and no app pool is ever
recycled.

Second problem it solves: to watch traffic on a server, engineers normally have to get onto the
server. portmirror exposes what it captures over a small HTTP API, so a dashboard can show many
machines at once and nobody needs to remote in to read a log.

## How it captures

Three mechanisms, chosen for what you need rather than layered on top of each other:

| Tier | Mechanism | Bodies | Same-host traffic | Cost |
|---|---|---|---|---|
| **ETW metadata** (shipping) | `Microsoft-Windows-HttpService` | no | **yes** | none — no restart, no install into the app |
| Packet capture (planned) | `pktmon`, built into Server 2019+ | yes | **no** — NDIS never sees the loopback fast path | none, but plaintext only |
| IIS module (planned) | server-level native/managed module | yes | yes | one recycle when installed, then toggled at runtime |

Worth knowing up front: packet capture cannot see traffic where the caller and callee are the
same machine, because Windows routes that through a loopback fast path that never reaches the
layer packet capture attaches to. The IIS module tier exists for exactly that gap — and it is
also the only place a response can be altered, which is what fault injection needs.

## Quick start

Requires Windows and an elevated prompt — creating an ETW session needs administrator rights.

```
portmirror.exe
```

Then open <http://localhost:9099>. Traffic to the box appears live.

Configure with `appsettings.json` next to the executable, `PORTMIRROR_`-prefixed environment
variables, or command line arguments:

```
portmirror.exe --Portmirror:Port=9099 --Portmirror:Capacity=5000
```

| Setting | Default | Meaning |
|---|---|---|
| `Portmirror:Port` | `9099` | Port for the API and UI |
| `Portmirror:Capacity` | `5000` | Exchanges retained in memory; oldest overwritten |
| `Portmirror:AutoStartCapture` | `true` | Begin capturing at startup |
| `Portmirror:RedactionEnabled` | `true` | Mask cards, credentials and tokens |
| `Portmirror:AuthToken` | none | When set, `/api/*` requires it in `X-Portmirror-Token` |
| `Portmirror:IdleTimeoutSeconds` | `30` | When to flush a request whose terminal event never arrived |

### Run as a Windows service

```
sc.exe create portmirror binPath= "C:\portmirror\portmirror.exe" start= auto
sc.exe start portmirror
```

The same binary detects it is running as a service; no separate build is needed.

## API

| Route | Purpose |
|---|---|
| `GET /` | Live-tail UI |
| `GET /healthz` | Liveness |
| `GET /api/agent` | Host, version, capture state, counters |
| `GET /api/exchanges?since=&limit=&q=&status=` | Captured exchanges; `since` is a sequence number |
| `GET /api/exchanges/{id}` | One exchange |
| `DELETE /api/exchanges` | Drop everything retained |
| `GET /api/stream?since=` | Server-sent events, live |
| `POST /api/capture/start` · `/stop` | Toggle capture with no restart |
| `GET /api/diagnostics/etw` | Which HTTP.SYS events were seen, and the payload fields they carry |

Every exchange carries a monotonic `seq`, so a client polls with `?since=N` and will neither
miss nor repeat a row.

## Please read this before pointing it at a real server

This is a traffic recorder. On an application server it will see card numbers, CVVs, bearer
tokens and cookies.

- Redaction is **on by default**. Card numbers are Luhn-checked and masked to the last four;
  credential headers and password/token/CVV fields are replaced. Leave it on.
- Redaction is a safety net, not a guarantee. It cannot know about a field name it has never
  been told about.
- Set `Portmirror:AuthToken` and keep the port off any untrusted network. There is no user
  model — anyone who can reach the port can read what was captured.
- Do not run this in production. Use it on test and QA machines, where observing traffic is
  the point.

## Roadmap

- [x] HTTP.SYS ETW capture, ring buffer, live-tail UI, single-file service
- [ ] Request and response bodies, pretty-printed as JSON and XML
- [ ] `pktmon` zero-touch mode for boxes where installing a module is not allowed
- [ ] Server-level IIS module: bodies for TLS-terminated sites and same-host traffic
- [ ] Fault injection — rules that force a 4xx/5xx or add latency, to exercise error handling
- [ ] Multi-agent aggregation, so one page can watch a whole fleet

## Building

Windows, .NET 8 SDK.

```
dotnet test tests/Portmirror.Tests/Portmirror.Tests.csproj
dotnet publish src/Portmirror.Agent/Portmirror.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
```

Capture itself needs Windows and elevation, so the ETW plumbing is kept separate from the
correlation, buffering and redaction logic — all of which is covered by unit tests that need
neither.

## License

MIT — see [LICENSE](LICENSE).

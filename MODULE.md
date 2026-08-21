# Portmirror IIS module

The in-process capture tier. Unlike the packet feed, it runs inside the IIS worker process, so it
sees **every** inbound request — including same-host (loopback) traffic — reads request and
response bodies directly, and can **inject fault responses**. It is the tier for complete,
continuous capture and for testing error handling.

## What it does and does not touch

- Reads the request body with `GetBufferedInputStream`, which does **not** consume the stream, so
  SOAP/WCF endpoints keep working.
- Reads the response body through a pass-through filter that never alters the bytes sent to the
  client.
- Redacts bodies and headers **in-process**, before anything leaves the worker, using the same
  redaction as every other tier.
- Sends captured exchanges to the agent off the request thread; if the agent is down, batches are
  dropped. Capture never slows or breaks the hosted application.

## Installing (one recycle, then never again)

Per application (simplest):

1. Copy the module's files (`Portmirror.IisModule.dll` and its dependencies) into the app's `bin`
   folder.
2. Register the module in the app's `web.config`:

   ```xml
   <configuration>
     <system.webServer>
       <modules>
         <add name="Portmirror" type="Portmirror.IisModule.PortmirrorHttpModule, Portmirror.IisModule" />
       </modules>
     </system.webServer>
   </configuration>
   ```

Adding the module recycles the application once. After that, everything is controlled by the file
below with **no further recycle**.

For a whole server, register the same `<add>` under `<system.webServer><modules>` in
`applicationHost.config` and place the assembly where the worker can load it (e.g. the GAC).

## Controlling it at runtime

The module reads `%ProgramData%\Portmirror\module.json`, re-reading it only when it changes.
Absent or malformed, the module stays **dormant** (captures nothing, injects nothing).

```json
{
  "captureEnabled": true,
  "agentUrl": "http://localhost:9099",
  "authToken": null,
  "maxBodyBytes": 262144,
  "faults": [
    { "method": "POST", "pathContains": "/api/payments", "status": 503, "body": "injected", "contentType": "text/plain" },
    { "pathContains": "/api/slow", "status": 0, "delayMs": 2000 }
  ]
}
```

- `captureEnabled` — master switch. Off by default.
- `agentUrl` — where captured exchanges are posted (`/api/ingest`).
- `authToken` — sent as `X-Portmirror-Token` when the agent requires it.
- `maxBodyBytes` — cap on each captured body.
- `faults` — rules evaluated in order; the first enabled match wins. `status > 0` replaces the
  response; `status: 0` with `delayMs` only delays. `method` / `pathContains` omitted means "any".

## Safety

This tier reads payloads that may contain card data and credentials. Redaction is on and runs
before exchanges leave the process, but treat any machine running it as sensitive, keep the agent
port off untrusted networks, and do not run it in production.

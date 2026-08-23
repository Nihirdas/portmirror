using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Portmirror.Agent.Capture;
using Portmirror.Agent.Http;
using Portmirror.Agent.Storage;

namespace Portmirror.Agent.Api;

public static class ApiEndpoints
{
    private const string UiResourceName = "Portmirror.Ui.index.html";
    private const string TokenHeader = "X-Portmirror-Token";

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>Requires the shared token on /api/* when one is configured.</summary>
    public static void UsePortmirrorAuth(this WebApplication app)
    {
        app.Use(async (ctx, next) =>
        {
            var configured = ctx.RequestServices.GetRequiredService<IOptions<AgentOptions>>().Value.AuthToken;

            if (!string.IsNullOrEmpty(configured) && ctx.Request.Path.StartsWithSegments("/api"))
            {
                var provided = ctx.Request.Headers[TokenHeader].FirstOrDefault()
                               ?? ctx.Request.Query["token"].FirstOrDefault();

                if (!string.Equals(provided, configured, StringComparison.Ordinal))
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await ctx.Response.WriteAsync("portmirror: missing or invalid token");
                    return;
                }
            }

            await next();
        });
    }

    public static void MapPortmirror(this WebApplication app)
    {
        app.MapGet("/", async ctx =>
        {
            ctx.Response.ContentType = "text/html; charset=utf-8";
            await ctx.Response.WriteAsync(LoadUi());
        });

        app.MapGet("/healthz", () => Results.Text("ok"));

        app.MapGet("/api/agent", (
            ExchangeRing ring,
            EtwCaptureService capture,
            IServiceProvider services,
            IOptions<AgentOptions> options) =>
        {
            var o = options.Value;
            var feed = services.GetService<Pcap.PcapFeedService>();

            return Results.Json(new
            {
                packetFeed = feed is null ? null : new
                {
                    running = feed.IsRunning,
                    filesProcessed = feed.FilesProcessed,
                    packetsSeen = feed.PacketsSeen,
                    exchangesEmitted = feed.ExchangesEmitted,
                    lastError = feed.LastError
                },
                product = "portmirror",
                version = Version(),
                host = Environment.MachineName,
                capturing = capture.IsCapturing,
                elevated = EtwCaptureService.IsElevated(),
                tier = nameof(CaptureTier.EtwMetadata),
                bodiesAvailable = services.GetService<Pcap.PcapFeedService>()?.IsRunning ?? false,
                eventsSeen = capture.EventsSeen,
                exchangesEmitted = capture.ExchangesEmitted,
                signalsUncorrelated = capture.SignalsUncorrelated,
                suppressedNoise = capture.SuppressedNoise,
                retained = ring.Count,
                capacity = ring.Capacity,
                lastSeq = ring.LastSeq,
                redactionEnabled = o.RedactionEnabled,
                authRequired = !string.IsNullOrEmpty(o.AuthToken)
            }, Json);
        });

        app.MapGet("/api/exchanges", (
            ExchangeRing ring,
            long? since,
            int? limit,
            string? q,
            int? status,
            string? direction,
            bool? bodies) =>
        {
            var take = Math.Clamp(limit ?? 200, 1, 2000);
            var filter = BuildFilter(q, status, direction, bodies);

            var found = since.HasValue
                ? ring.Since(since.Value, take, filter)
                : ring.Latest(take, filter);

            var items = found.Select(ToSummary).ToList();
            return Results.Json(new { lastSeq = ring.LastSeq, count = items.Count, items }, Json);
        });

        app.MapGet("/api/exchanges/{id}", (ExchangeRing ring, string id) =>
        {
            var found = ring.ById(id);

            if (found is null)
            {
                return Results.NotFound();
            }

            return Results.Json(new
            {
                exchange = found,
                formatted = new
                {
                    request = Formatted(found.Request),
                    response = Formatted(found.Response)
                }
            }, Json);
        });

        app.MapDelete("/api/exchanges", (ExchangeRing ring) =>
        {
            ring.Clear();
            return Results.Json(new { cleared = true }, Json);
        });

        // Dump the whole retained session to a downloadable file, so a capture can be archived or
        // handed to something else to read. 'raw' (default) is a flat text transcript — headers and
        // bodies, both directions — that reads well and feeds cleanly into other tools; 'json' is the
        // lossless structured form. The current filter (q/status/direction/bodies) narrows the dump.
        app.MapGet("/api/export", (
            HttpContext ctx,
            ExchangeRing ring,
            string? format,
            string? q,
            int? status,
            string? direction,
            bool? bodies) =>
        {
            var filter = BuildFilter(q, status, direction, bodies);
            var items = ring.Latest(int.MaxValue, filter).Reverse().ToList();   // oldest first
            var json = string.Equals(format, "json", StringComparison.OrdinalIgnoreCase);
            var ext = json ? "json" : "txt";
            var name = $"portmirror-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmmss}.{ext}";

            var payload = json
                ? JsonSerializer.Serialize(
                    new { host = Environment.MachineName, version = Version(), count = items.Count, exchanges = items },
                    Json)
                : RawDump(items);

            ctx.Response.Headers.ContentDisposition = $"attachment; filename=\"{name}\"";
            return Results.Text(payload, json ? "application/json" : "text/plain; charset=utf-8");
        });

        // Exchanges captured out-of-process by the IIS module are posted here. They arrive already
        // redacted by the module; the tier is forced so a client cannot mislabel its source.
        app.MapPost("/api/ingest", async (HttpContext ctx, ExchangeRing ring) =>
        {
            List<Capture.Exchange>? items;
            try
            {
                items = await JsonSerializer.DeserializeAsync<List<Capture.Exchange>>(ctx.Request.Body, Json);
            }
            catch (JsonException)
            {
                return Results.BadRequest(new { error = "invalid exchange payload" });
            }

            if (items is null)
            {
                return Results.BadRequest(new { error = "empty payload" });
            }

            var ingested = 0;
            foreach (var exchange in items)
            {
                exchange.Tier = CaptureTier.IisModule;
                if (exchange.StartedUtc == default)
                {
                    exchange.StartedUtc = DateTimeOffset.UtcNow;
                }

                exchange.CompletedUtc ??= exchange.StartedUtc;
                ring.Append(exchange);
                ingested++;
            }

            return Results.Json(new { ingested }, Json);
        });

        // The point of the whole tool: capture toggles under a running application,
        // with no app pool recycle.
        app.MapPost("/api/capture/start", (EtwCaptureService capture) =>
        {
            var problem = capture.TryStartCapture();

            return problem is null
                ? Results.Json(new { capturing = true }, Json)
                : Results.Json(new { capturing = capture.IsCapturing, error = problem }, Json,
                    statusCode: StatusCodes.Status503ServiceUnavailable);
        });

        app.MapPost("/api/capture/stop", (EtwCaptureService capture) =>
        {
            capture.StopCapture();
            return Results.Json(new { capturing = false }, Json);
        });

        // The packet (body) feed: captures request/response payloads via pktmon, no recycle.
        app.MapPost("/api/capture/packets/start", (IServiceProvider services) =>
        {
            var feed = services.GetService<Pcap.PcapFeedService>();
            if (feed is null)
            {
                return Results.Json(new { running = false, error = "Packet capture is available on Windows only." },
                    Json, statusCode: StatusCodes.Status501NotImplemented);
            }

            var problem = feed.TryStart();
            return problem is null
                ? Results.Json(new { running = true }, Json)
                : Results.Json(new { running = feed.IsRunning, error = problem }, Json,
                    statusCode: StatusCodes.Status503ServiceUnavailable);
        });

        app.MapPost("/api/capture/packets/stop", (IServiceProvider services) =>
        {
            services.GetService<Pcap.PcapFeedService>()?.Stop();
            return Results.Json(new { running = false }, Json);
        });

        // Reports the payload fields HTTP.SYS actually emits on this Windows build, so
        // mapping a new build is a lookup instead of guesswork.
        app.MapGet("/api/diagnostics/etw", (EtwCaptureService capture) =>
            Results.Json(new
            {
                provider = "Microsoft-Windows-HttpService",
                session = EtwCaptureService.SessionName,
                observedEvents = capture.ObservedEvents.ToDictionary(
                    kv => kv.Key,
                    kv => new
                    {
                        fields = kv.Value.Fields,
                        sample = kv.Value.Sample,
                        mappedTo = EtwCaptureService.MapKind(kv.Key).ToString()
                    })
            }, Json));

        app.MapGet("/api/stream", StreamExchanges);
    }

    private static async Task StreamExchanges(
        HttpContext ctx, ExchangeRing ring, long? since, string? q, int? status,
        string? direction, bool? bodies)
    {
        ctx.Response.ContentType = "text/event-stream";
        ctx.Response.Headers.CacheControl = "no-cache";
        ctx.Response.Headers["X-Accel-Buffering"] = "no";

        var filter = BuildFilter(q, status, direction, bodies);
        var cursor = since ?? ring.LastSeq;
        var ct = ctx.RequestAborted;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var batch = ring.Since(cursor, 200, filter);

                foreach (var exchange in batch)
                {
                    cursor = exchange.Seq;
                    await ctx.Response.WriteAsync(
                        $"data: {JsonSerializer.Serialize(ToSummary(exchange), Json)}\n\n", ct);
                }

                if (batch.Count == 0)
                {
                    // Comment frame keeps intermediaries from closing an idle stream.
                    await ctx.Response.WriteAsync(": keepalive\n\n", ct);
                }

                await ctx.Response.Body.FlushAsync(ct);
                await Task.Delay(400, ct);
            }
        }
        catch (OperationCanceledException)
        {
            // Client went away; nothing to do.
        }
    }

    /// <summary>
    /// A listing- and stream-friendly view of an exchange: every scalar field, plus a small
    /// per-message body summary, but never the body text itself. Bodies can be large, so they
    /// are fetched one at a time from the detail endpoint rather than streamed for every row.
    /// </summary>
    private static object ToSummary(Capture.Exchange e) => new
    {
        e.Seq,
        e.Id,
        e.CorrelationId,
        e.StartedUtc,
        e.CompletedUtc,
        e.DurationMs,
        e.Verb,
        e.Url,
        e.StatusCode,
        e.ClientIp,
        e.SiteId,
        e.QueueName,
        tier = e.Tier.ToString(),
        direction = e.Direction.ToString(),
        e.Partial,
        request = MessageSummary(e.Request),
        response = MessageSummary(e.Response)
    };

    private static object? MessageSummary(Capture.HttpMessage? m) => m is null ? null : new
    {
        m.ContentType,
        m.BodyFormat,
        m.BodyByteCount,
        hasBody = m.Body is not null,
        m.BodyTruncated,
        m.BodyRedacted,
        m.DecodeError
    };

    /// <summary>A flat text transcript of a set of exchanges: one block each, headers and body for
    /// both directions. Bodies are already decompressed and redacted by the time they land here.</summary>
    internal static string RawDump(IReadOnlyList<Capture.Exchange> items)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("portmirror session export  ")
          .Append(items.Count).Append(" exchanges  ")
          .Append(Environment.MachineName).Append('\n');

        foreach (var e in items)
        {
            sb.Append("\n================================================================\n")
              .Append('#').Append(e.Seq).Append("  ").Append(e.StartedUtc.ToString("O"))
              .Append("  [").Append(e.Tier).Append('/').Append(e.Direction).Append(']');
            if (e.Partial) { sb.Append("  (partial)"); }
            sb.Append('\n');

            sb.Append(e.Verb ?? "-").Append(' ').Append(e.Url ?? "(no url)")
              .Append("  ->  ").Append(e.StatusCode?.ToString() ?? "-");
            if (e.DurationMs is not null) { sb.Append("  ").Append(e.DurationMs.Value.ToString("0.#")).Append("ms"); }
            if (e.ClientIp is not null) { sb.Append("  client=").Append(e.ClientIp); }
            if (e.QueueName is not null) { sb.Append("  queue=").Append(e.QueueName); }
            sb.Append('\n');

            AppendMessage(sb, "REQUEST", e.Request);
            AppendMessage(sb, "RESPONSE", e.Response);
        }

        return sb.ToString();
    }

    private static void AppendMessage(System.Text.StringBuilder sb, string title, Capture.HttpMessage? m)
    {
        if (m is null) { return; }

        sb.Append("---------------- ").Append(title).Append(" ----------------\n");
        foreach (var h in m.Headers)
        {
            sb.Append(h.Key).Append(": ").Append(h.Value).Append('\n');
        }

        if (m.Body is not null)
        {
            sb.Append('\n').Append(m.Body).Append('\n');
        }
        else if (m.BodyFormat == "binary")
        {
            sb.Append("\n[binary body, ").Append(m.BodyByteCount).Append(" bytes]\n");
        }
    }

    private static object? Formatted(Capture.HttpMessage? m)
    {
        if (m?.Body is null)
        {
            return null;
        }

        return new
        {
            format = m.BodyFormat,
            pretty = BodyFormatter.Pretty(m.Body, m.ContentType)
        };
    }

    internal static Func<Capture.Exchange, bool>? BuildFilter(
        string? q, int? status, string? direction = null, bool? bodies = null)
    {
        var hasDirection = Enum.TryParse<Capture.CaptureDirection>(direction, ignoreCase: true, out var wantDir);

        if (string.IsNullOrWhiteSpace(q) && !status.HasValue && !hasDirection && bodies != true)
        {
            return null;
        }

        var needle = q?.Trim();

        return exchange =>
        {
            if (status.HasValue && exchange.StatusCode != status.Value)
            {
                return false;
            }

            if (hasDirection && exchange.Direction != wantDir)
            {
                return false;
            }

            if (bodies == true && exchange.Request?.Body is null && exchange.Response?.Body is null)
            {
                return false;
            }

            if (string.IsNullOrEmpty(needle))
            {
                return true;
            }

            return Contains(exchange.Url, needle)
                   || Contains(exchange.Verb, needle)
                   || Contains(exchange.ClientIp, needle)
                   || Contains(exchange.QueueName, needle);
        };

        static bool Contains(string? haystack, string needle) =>
            haystack is not null && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private static string Version() =>
        typeof(AgentOptions).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(AgentOptions).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    private static string LoadUi()
    {
        var assembly = typeof(AgentOptions).Assembly;
        using var stream = assembly.GetManifestResourceStream(UiResourceName);

        if (stream is null)
        {
            return "<!doctype html><title>portmirror</title><p>UI resource missing from this build.</p>";
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

using System.Security.Principal;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Options;
using Portmirror.Agent.Storage;

namespace Portmirror.Agent.Capture;

/// <summary>
/// Captures inbound HTTP from the HTTP.SYS ETW provider.
///
/// This is deliberately not a proxy. Fiddler and friends capture by becoming the machine's
/// proxy, but a .NET worker process resolves its proxy once at startup, so a w3wp that was
/// already running never routes through it — which is why Fiddler needs an app pool recycle.
/// Reading HTTP.SYS instead means capture can be switched on and off underneath a running
/// application, with no recycle, ever.
///
/// The agent serves its own API over Kestrel rather than HTTP.SYS, so it does not observe
/// itself and cannot feed back into its own capture.
/// </summary>
public sealed class EtwCaptureService : IHostedService, IDisposable
{
    public const string SessionName = "Portmirror";
    private const string ProviderName = "Microsoft-Windows-HttpService";

    private readonly ExchangeRing _ring;
    private readonly Redaction.Redactor _redactor;
    private readonly AgentOptions _options;
    private readonly ILogger<EtwCaptureService> _logger;
    private readonly ExchangeCorrelator _correlator;

    /// <summary>Guards the correlator: the ETW callback thread and the sweep timer both touch it.</summary>
    private readonly object _sync = new();

    private readonly Dictionary<string, EventShape> _observedEvents = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>An event's payload field names plus one sampled value each, for diagnostics.</summary>
    public sealed record EventShape(string[] Fields, Dictionary<string, string> Sample);

    private TraceEventSession? _session;
    private Thread? _pump;
    private Timer? _sweepTimer;
    private long _eventsSeen;
    private long _exchangesEmitted;
    private long _signalsUncorrelated;
    private long _suppressed;
    private volatile bool _capturing;
    private bool _disposed;

    public EtwCaptureService(
        ExchangeRing ring,
        Redaction.Redactor redactor,
        IOptions<AgentOptions> options,
        ILogger<EtwCaptureService> logger)
    {
        _ring = ring;
        _redactor = redactor;
        _options = options.Value;
        _logger = logger;
        _correlator = new ExchangeCorrelator(TimeSpan.FromSeconds(_options.IdleTimeoutSeconds));
    }

    public bool IsCapturing => _capturing;
    public long EventsSeen => Interlocked.Read(ref _eventsSeen);
    public long ExchangesEmitted => Interlocked.Read(ref _exchangesEmitted);
    public long SignalsUncorrelated => Interlocked.Read(ref _signalsUncorrelated);

    /// <summary>Content-less connection-noise exchanges dropped rather than stored. See <see cref="Emit"/>.</summary>
    public long SuppressedNoise => Interlocked.Read(ref _suppressed);

    /// <summary>
    /// Event names seen so far mapped to the payload fields they actually carry. HTTP.SYS field
    /// names drift between Windows builds, so this is exposed over the API to make field
    /// mapping on a new build a lookup rather than a guess.
    /// </summary>
    public IReadOnlyDictionary<string, EventShape> ObservedEvents
    {
        get { lock (_sync) { return new Dictionary<string, EventShape>(_observedEvents); } }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _sweepTimer = new Timer(
            static state => ((EtwCaptureService)state!).SweepIdle(),
            this,
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(5));

        if (_options.AutoStartCapture)
        {
            TryStartCapture();
        }
        else
        {
            _logger.LogInformation("Capture is idle. POST /api/capture/start to begin.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        StopCapture();
        _sweepTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        return Task.CompletedTask;
    }

    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Starts capture. Returns the reason it could not start, or null on success.</summary>
    public string? TryStartCapture()
    {
        lock (_sync)
        {
            if (_capturing)
            {
                return null;
            }

            if (!IsElevated())
            {
                const string reason = "Creating an ETW session requires administrator rights.";
                _logger.LogError("{Reason}", reason);
                return reason;
            }

            try
            {
                _session = new TraceEventSession(SessionName) { StopOnDispose = true };
                _session.EnableProvider(ProviderName, TraceEventLevel.Verbose);
                _session.Source.Dynamic.All += OnEtwEvent;
            }
            catch (Exception ex)
            {
                _session?.Dispose();
                _session = null;

                var reason =
                    $"Could not start ETW session '{SessionName}': {ex.Message} " +
                    $"If a session was leaked by an earlier crash, clear it with: logman stop {SessionName} -ets";
                _logger.LogError(ex, "{Reason}", reason);
                return reason;
            }

            // Source.Process() blocks for the lifetime of the session, so it needs its own
            // thread rather than a pool thread.
            _pump = new Thread(PumpEvents)
            {
                IsBackground = true,
                Name = "portmirror-etw"
            };

            _capturing = true;
            _pump.Start();

            _logger.LogInformation(
                "Capture started on {Provider} (session {Session}).", ProviderName, SessionName);
            return null;
        }
    }

    public void StopCapture()
    {
        Thread? pump;

        lock (_sync)
        {
            if (!_capturing)
            {
                return;
            }

            _capturing = false;
            pump = _pump;
            _pump = null;

            try
            {
                _session?.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disposing ETW session.");
            }

            _session = null;
        }

        // Disposing the session unblocks Process(); give the pump a moment to unwind.
        pump?.Join(TimeSpan.FromSeconds(5));
        _logger.LogInformation("Capture stopped.");
    }

    private void PumpEvents()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex) when (!_capturing)
        {
            _logger.LogDebug(ex, "ETW pump ended during shutdown.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ETW pump failed; capture has stopped.");
            _capturing = false;
        }
    }

    private void OnEtwEvent(TraceEvent data)
    {
        Interlocked.Increment(ref _eventsSeen);

        var kind = MapKind(data.EventName);
        var correlationId = CorrelationIdOf(data);

        if (correlationId is null)
        {
            Interlocked.Increment(ref _signalsUncorrelated);
            return;
        }

        var signal = new EtwSignal(
            correlationId,
            kind,
            data.TimeStamp.ToUniversalTime(),
            Verb: NormalizeVerb(TryString(data, "Verb", "HttpVerb", "Method")),
            Url: TryString(data, "Url", "Uri", "UriStem", "RequestUri"),
            StatusCode: TryInt(data, "StatusCode", "HttpStatus"),
            ClientIp: TryAddress(data, "RemoteAddr", "RemoteAddress", "ClientAddr"),
            SiteId: TryString(data, "SiteId", "SiteID"),
            QueueName: TryString(data, "RequestQueueName", "QueueName", "AppPoolName"));

        Exchange? completed;

        lock (_sync)
        {
            RecordEventShape(data);
            completed = _correlator.Accept(signal);
        }

        if (completed is not null)
        {
            Emit(completed);
        }
    }

    /// <summary>
    /// Appends an exchange to the ring unless it is content-less connection noise. F5 and other
    /// TCP health monitors open a socket without sending an HTTP request, so HTTP.SYS still
    /// completes an exchange — one carrying a client address but no verb, URL or status. Those
    /// rows tell nobody anything, and at health-check volume they fill the ring and evict the
    /// body-bearing captures that do matter, so they are dropped here rather than stored.
    /// </summary>
    private void Emit(Exchange exchange)
    {
        if (IsContentless(exchange))
        {
            Interlocked.Increment(ref _suppressed);
            return;
        }

        _ring.Append(exchange);
        Interlocked.Increment(ref _exchangesEmitted);
    }

    /// <summary>
    /// True when an exchange carries no HTTP request or response line at all — no verb, URL or
    /// status. HTTP.SYS still completes these for connection-only activity such as TCP health
    /// probes, but they hold no information worth storing.
    /// </summary>
    internal static bool IsContentless(Exchange e) =>
        e.Verb is null && e.Url is null && e.StatusCode is null;

    /// <summary>Remembers the payload field names each event carries, for the diagnostics endpoint.</summary>
    private void RecordEventShape(TraceEvent data)
    {
        var name = data.EventName ?? "(unnamed)";
        if (_observedEvents.ContainsKey(name))
        {
            return;
        }

        try
        {
            var names = data.PayloadNames ?? Array.Empty<string>();
            var sample = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var field in names)
            {
                try
                {
                    var value = data.PayloadByName(field)?.ToString() ?? "(null)";

                    if (value.Length > 120)
                    {
                        value = value[..120] + "...";
                    }

                    sample[field] = _redactor.RedactBody(value) ?? value;
                }
                catch
                {
                    sample[field] = "(unreadable)";
                }
            }

            _observedEvents[name] = new EventShape(names.ToArray(), sample);
        }
        catch
        {
            _observedEvents[name] = new EventShape(Array.Empty<string>(), new Dictionary<string, string>());
        }
    }

    private void SweepIdle()
    {
        try
        {
            IReadOnlyList<Exchange> flushed;

            lock (_sync)
            {
                flushed = _correlator.Sweep(DateTimeOffset.UtcNow);
            }

            foreach (var exchange in flushed)
            {
                Emit(exchange);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Idle sweep failed.");
        }
    }

    /// <summary>
    /// HTTP.SYS event names are matched by substring on purpose: the manifest renders them
    /// differently across Windows builds, and a missed match degrades to Other rather than
    /// dropping the request.
    /// </summary>
    internal static SignalKind MapKind(string? eventName)
    {
        if (string.IsNullOrEmpty(eventName))
        {
            return SignalKind.Other;
        }

        // Ordered most-specific first.
        if (Has(eventName, "SrvdFrmCache") || Has(eventName, "CachedAndSend"))
        {
            return SignalKind.CacheServed;
        }

        // SendComplete is the terminal event on Server 2019/2022. Those builds emit no
        // EndRequest at all, so treating only EndRequest as terminal means nothing ever
        // completes. EndRequest is kept below for builds that do emit it.
        if (Has(eventName, "SendComplete"))
        {
            return SignalKind.RequestEnded;
        }

        // A rejected request has no further lifecycle, so it terminates here.
        if (Has(eventName, "Rejected"))
        {
            return SignalKind.RequestEnded;
        }

        if (Has(eventName, "EndRequest") || Has(eventName, "RequestEnd"))
        {
            return SignalKind.RequestEnded;
        }

        if (Has(eventName, "FastResp") || Has(eventName, "SendResp")
            || Has(eventName, "RespLast") || Has(eventName, "FastSend")
            || Has(eventName, "Response"))
        {
            return SignalKind.ResponseSent;
        }

        if (Has(eventName, "RecvReq") || Has(eventName, "RequestRecv"))
        {
            return SignalKind.RequestReceived;
        }

        if (Has(eventName, "Parse"))
        {
            return SignalKind.RequestParsed;
        }

        if (Has(eventName, "Deliver"))
        {
            return SignalKind.Delivered;
        }

        return SignalKind.Other;

        static bool Has(string haystack, string needle) =>
            haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Correlates on RequestId, which every request-scoped HTTP.SYS event carries except Parse.
    /// Parse is keyed by RequestObj (a pointer) instead, so it is deliberately dropped rather
    /// than given its own bogus key — Deliver reports the same Url and does carry RequestId.
    /// Connection-scoped events carry neither and are dropped for the same reason.
    /// </summary>
    private static string? CorrelationIdOf(TraceEvent data)
    {
        // RequestId is the stable HTTP.SYS request identity and is present on every
        // request-scoped event except Parse. ActivityID is populated but is NOT stable across
        // one request's events on Server 2022, so using it splits each request into fragments.
        var requestId = TryString(data, "RequestId", "ContextId");

        if (requestId is not null)
        {
            return requestId;
        }

        return data.ActivityID != Guid.Empty ? data.ActivityID.ToString("n") : null;
    }

    /// <summary>
    /// HTTP.SYS reports the verb as an enum ordinal on some events (Parse) and as text on
    /// others, so "4" has to become "GET" before anyone looks at it.
    /// </summary>
    internal static string? NormalizeVerb(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        if (!int.TryParse(raw, out var ordinal))
        {
            return raw;
        }

        return ordinal switch
        {
            3 => "OPTIONS",
            4 => "GET",
            5 => "HEAD",
            6 => "POST",
            7 => "PUT",
            8 => "DELETE",
            9 => "TRACE",
            10 => "CONNECT",
            11 => "TRACK",
            12 => "MOVE",
            13 => "COPY",
            14 => "PROPFIND",
            15 => "PROPPATCH",
            16 => "MKCOL",
            17 => "LOCK",
            18 => "UNLOCK",
            19 => "SEARCH",
            _ => null
        };
    }

    private static string? TryString(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                var value = data.PayloadByName(name);
                var text = value?.ToString();

                // Binary payloads (RemoteAddr is a sockaddr) stringify to a type name;
                // surfacing "System.Byte[]" in the UI would be worse than reporting nothing.
                if (!string.IsNullOrWhiteSpace(text) && !text.StartsWith("System.", StringComparison.Ordinal))
                {
                    return text;
                }
            }
            catch
            {
                // Field absent on this Windows build; try the next alias.
            }
        }

        return null;
    }

    /// <summary>
    /// RemoteAddr is a raw SOCKADDR, so it stringifies to "System.Byte[]". Decode it into an
    /// address instead — knowing which host called is most of the value of an inbound capture.
    /// </summary>
    private static string? TryAddress(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                if (data.PayloadByName(name) is byte[] raw)
                {
                    var parsed = ParseSockAddr(raw);

                    if (parsed is not null)
                    {
                        return parsed;
                    }
                }
            }
            catch
            {
                // Field absent on this Windows build; try the next alias.
            }
        }

        return null;
    }

    /// <summary>
    /// SOCKADDR_IN is family(2) port(2) addr(4); SOCKADDR_IN6 is family(2) port(2)
    /// flowinfo(4) addr(16). Family is a little-endian short: 2 = AF_INET, 23 = AF_INET6.
    /// </summary>
    internal static string? ParseSockAddr(byte[]? raw)
    {
        if (raw is null || raw.Length < 8)
        {
            return null;
        }

        var family = raw[0] | (raw[1] << 8);

        switch (family)
        {
            case 2:
                return $"{raw[4]}.{raw[5]}.{raw[6]}.{raw[7]}";

            case 23 when raw.Length >= 24:
                var v6 = new byte[16];
                Array.Copy(raw, 8, v6, 0, 16);
                return new System.Net.IPAddress(v6).ToString();

            default:
                return null;
        }
    }

    private static int? TryInt(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                var value = data.PayloadByName(name);
                if (value is null)
                {
                    continue;
                }

                if (value is int i)
                {
                    return i == 0 ? null : i;
                }

                if (int.TryParse(value.ToString(), out var parsed) && parsed != 0)
                {
                    return parsed;
                }
            }
            catch
            {
                // Field absent on this Windows build; try the next alias.
            }
        }

        return null;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        StopCapture();
        _sweepTimer?.Dispose();
    }
}

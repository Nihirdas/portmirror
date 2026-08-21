namespace Portmirror.Agent.Capture;

/// <summary>
/// Stitches the several HTTP.SYS events that make up one request into a single
/// <see cref="Exchange"/>. Not thread-safe by design: drive it from the single ETW
/// callback thread, or guard it yourself.
/// </summary>
public sealed class ExchangeCorrelator
{
    private sealed class Pending
    {
        public required Exchange Exchange { get; init; }
        public DateTimeOffset LastTouchedUtc { get; set; }
    }

    private readonly Dictionary<string, Pending> _pending = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Ids finished recently. HTTP.SYS keeps emitting events for a request after its outcome
    /// is known (FastRespLast, FastSend, SendComplete), and without this those trailing events
    /// would each start a fresh exchange under the same RequestId.
    /// </summary>
    private readonly Dictionary<string, DateTimeOffset> _recentlyCompleted =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly TimeSpan _idleTimeout;
    private readonly int _maxPending;

    public ExchangeCorrelator(TimeSpan? idleTimeout = null, int maxPending = 10_000)
    {
        _idleTimeout = idleTimeout ?? TimeSpan.FromSeconds(30);
        _maxPending = maxPending < 1 ? 1 : maxPending;
    }

    public int PendingCount => _pending.Count;

    /// <summary>
    /// Folds one signal in. Returns the finished exchange when this signal terminates it,
    /// otherwise null.
    /// </summary>
    public Exchange? Accept(EtwSignal signal)
    {
        if (string.IsNullOrEmpty(signal.CorrelationId))
        {
            return null;
        }

        if (_recentlyCompleted.ContainsKey(signal.CorrelationId))
        {
            return null;
        }

        if (!_pending.TryGetValue(signal.CorrelationId, out var pending))
        {
            pending = new Pending
            {
                Exchange = new Exchange
                {
                    CorrelationId = signal.CorrelationId,
                    StartedUtc = signal.TimestampUtc,
                    Tier = CaptureTier.EtwMetadata
                },
                LastTouchedUtc = signal.TimestampUtc
            };
            _pending[signal.CorrelationId] = pending;
            TrimIfOverCapacity();
        }

        var exchange = pending.Exchange;
        pending.LastTouchedUtc = signal.TimestampUtc;

        // First non-null wins for identity fields; status is allowed to be overwritten
        // because a request can legitimately report more than one response event.
        exchange.Verb ??= signal.Verb;
        exchange.Url ??= signal.Url;
        exchange.ClientIp ??= signal.ClientIp;
        exchange.SiteId ??= signal.SiteId;
        exchange.QueueName ??= signal.QueueName;

        if (signal.StatusCode.HasValue)
        {
            exchange.StatusCode = signal.StatusCode;
        }

        if (signal.TimestampUtc < exchange.StartedUtc)
        {
            exchange.StartedUtc = signal.TimestampUtc;
        }

        // Completing on "the outcome is known" rather than on a specific terminal event.
        // Which event actually ends a request varies by Windows build — Server 2022 emits no
        // EndRequest at all, and SendComplete does not always arrive — so waiting for one
        // means exchanges either never complete or only appear via the idle sweep. Once a
        // status code has been reported the exchange is complete for observation purposes.
        var outcomeKnown = signal.Kind == SignalKind.ResponseSent && exchange.StatusCode.HasValue;
        var terminal = signal.Kind is SignalKind.RequestEnded or SignalKind.CacheServed || outcomeKnown;

        if (!terminal)
        {
            return null;
        }

        _pending.Remove(signal.CorrelationId);
        _recentlyCompleted[signal.CorrelationId] = signal.TimestampUtc;
        Complete(exchange, signal.TimestampUtc, partial: false);
        return exchange;
    }

    /// <summary>
    /// Flushes anything that has gone quiet for longer than the idle timeout. Those come out
    /// flagged <see cref="Exchange.Partial"/> — the request was seen, its terminal event was not.
    /// </summary>
    public IReadOnlyList<Exchange> Sweep(DateTimeOffset nowUtc)
    {
        PruneRecentlyCompleted(nowUtc);

        if (_pending.Count == 0)
        {
            return Array.Empty<Exchange>();
        }

        List<Exchange>? flushed = null;
        List<string>? expired = null;

        foreach (var (key, pending) in _pending)
        {
            if (nowUtc - pending.LastTouchedUtc < _idleTimeout)
            {
                continue;
            }

            (expired ??= new List<string>()).Add(key);
            Complete(pending.Exchange, pending.LastTouchedUtc, partial: true);
            (flushed ??= new List<Exchange>()).Add(pending.Exchange);
        }

        if (expired is not null)
        {
            foreach (var key in expired)
            {
                _pending.Remove(key);
            }
        }

        return flushed ?? (IReadOnlyList<Exchange>)Array.Empty<Exchange>();
    }

    /// <summary>Forgets finished ids once their trailing events can no longer arrive.</summary>
    private void PruneRecentlyCompleted(DateTimeOffset nowUtc)
    {
        if (_recentlyCompleted.Count == 0)
        {
            return;
        }

        var cutoff = nowUtc - _idleTimeout;
        List<string>? stale = null;

        foreach (var (key, completedUtc) in _recentlyCompleted)
        {
            if (completedUtc < cutoff)
            {
                (stale ??= new List<string>()).Add(key);
            }
        }

        if (stale is null)
        {
            // Hard cap in case a flood arrives faster than the sweep interval.
            if (_recentlyCompleted.Count <= _maxPending * 2)
            {
                return;
            }

            _recentlyCompleted.Clear();
            return;
        }

        foreach (var key in stale)
        {
            _recentlyCompleted.Remove(key);
        }
    }

    /// <summary>Finished ids currently being suppressed. Exposed for tests and diagnostics.</summary>
    public int RecentlyCompletedCount => _recentlyCompleted.Count;

    private static void Complete(Exchange exchange, DateTimeOffset completedUtc, bool partial)
    {
        exchange.CompletedUtc = completedUtc;
        exchange.DurationMs = Math.Round((completedUtc - exchange.StartedUtc).TotalMilliseconds, 3);
        exchange.Partial = partial;
    }

    /// <summary>
    /// Guards against unbounded growth when terminal events go missing. Scans on overflow only,
    /// which is rare enough that the O(n) pass does not matter.
    /// </summary>
    private void TrimIfOverCapacity()
    {
        if (_pending.Count <= _maxPending)
        {
            return;
        }

        var oldestKey = string.Empty;
        var oldest = DateTimeOffset.MaxValue;

        foreach (var (key, pending) in _pending)
        {
            if (pending.LastTouchedUtc < oldest)
            {
                oldest = pending.LastTouchedUtc;
                oldestKey = key;
            }
        }

        if (oldestKey.Length > 0)
        {
            _pending.Remove(oldestKey);
        }
    }
}

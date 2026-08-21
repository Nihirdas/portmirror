using Portmirror.Agent.Capture;

namespace Portmirror.Agent.Storage;

/// <summary>
/// Fixed-capacity, thread-safe ring of exchanges. Oldest is overwritten once full, so the
/// agent's memory use is bounded no matter how long it runs or how loud the box gets.
/// Every entry carries a monotonic <see cref="Exchange.Seq"/> so clients can poll
/// incrementally with "give me everything after N" and never miss or repeat a row.
/// </summary>
public sealed class ExchangeRing
{
    private readonly object _gate = new();
    private readonly Exchange?[] _items;
    private long _nextSeq = 1;
    private int _writeIndex;
    private int _count;

    public ExchangeRing(int capacity)
    {
        if (capacity < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity), "Capacity must be at least 1.");
        }

        _items = new Exchange?[capacity];
    }

    public int Capacity => _items.Length;

    public int Count
    {
        get { lock (_gate) { return _count; } }
    }

    /// <summary>Sequence of the most recent entry, or 0 when empty.</summary>
    public long LastSeq
    {
        get { lock (_gate) { return _nextSeq - 1; } }
    }

    /// <summary>Total ever appended, including entries since overwritten.</summary>
    public long TotalAppended
    {
        get { lock (_gate) { return _nextSeq - 1; } }
    }

    public long Append(Exchange exchange)
    {
        ArgumentNullException.ThrowIfNull(exchange);

        lock (_gate)
        {
            exchange.Seq = _nextSeq++;
            _items[_writeIndex] = exchange;
            _writeIndex = (_writeIndex + 1) % _items.Length;

            if (_count < _items.Length)
            {
                _count++;
            }

            return exchange.Seq;
        }
    }

    /// <summary>Entries with a sequence strictly greater than <paramref name="afterSeq"/>, oldest first.</summary>
    public IReadOnlyList<Exchange> Since(long afterSeq, int limit, Func<Exchange, bool>? filter = null)
    {
        if (limit < 1)
        {
            return Array.Empty<Exchange>();
        }

        var matches = Snapshot(e => e.Seq > afterSeq && (filter is null || filter(e)));
        matches.Sort(static (a, b) => a.Seq.CompareTo(b.Seq));

        return matches.Count > limit ? matches.GetRange(0, limit) : matches;
    }

    /// <summary>The most recent entries, newest first.</summary>
    public IReadOnlyList<Exchange> Latest(int limit, Func<Exchange, bool>? filter = null)
    {
        if (limit < 1)
        {
            return Array.Empty<Exchange>();
        }

        var matches = Snapshot(e => filter is null || filter(e));
        matches.Sort(static (a, b) => b.Seq.CompareTo(a.Seq));

        return matches.Count > limit ? matches.GetRange(0, limit) : matches;
    }

    public Exchange? ById(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return null;
        }

        lock (_gate)
        {
            foreach (var item in _items)
            {
                if (item is not null && string.Equals(item.Id, id, StringComparison.OrdinalIgnoreCase))
                {
                    return item;
                }
            }
        }

        return null;
    }

    public void Clear()
    {
        lock (_gate)
        {
            Array.Clear(_items, 0, _items.Length);
            _writeIndex = 0;
            _count = 0;
        }
    }

    private List<Exchange> Snapshot(Func<Exchange, bool> predicate)
    {
        var result = new List<Exchange>();

        lock (_gate)
        {
            foreach (var item in _items)
            {
                if (item is not null && predicate(item))
                {
                    result.Add(item);
                }
            }
        }

        return result;
    }
}

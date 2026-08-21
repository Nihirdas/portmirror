namespace Portmirror.Agent.Http;

/// <summary>
/// Puts one direction of a TCP conversation back into order.
///
/// Captured segments arrive out of order, duplicated, and partially overlapping, and a parser
/// fed that directly produces garbage. This hands back only bytes that are contiguous from
/// where the stream left off, buffering anything from the future until the gap in front of it
/// is filled — and giving up on a gap that never fills, rather than stalling the connection
/// forever.
/// </summary>
public sealed class TcpStreamAssembler
{
    private const int DefaultMaxBuffered = 4 * 1024 * 1024;

    private readonly Dictionary<uint, byte[]> _pending = new();
    private readonly int _maxBuffered;
    private uint _next;
    private int _buffered;

    public TcpStreamAssembler(uint initialSequence, int maxBufferedBytes = DefaultMaxBuffered)
    {
        _next = initialSequence;
        _maxBuffered = maxBufferedBytes < 4096 ? 4096 : maxBufferedBytes;
    }

    /// <summary>Sequence number the stream is waiting for.</summary>
    public uint NextSequence => _next;

    public int PendingSegments => _pending.Count;
    public int PendingBytes => _buffered;
    public long DeliveredBytes { get; private set; }

    /// <summary>Bytes discarded as duplicates or as overtaken by a skipped gap.</summary>
    public long DiscardedBytes { get; private set; }

    /// <summary>
    /// Offers one segment. Returns whatever is now contiguous, which may be empty (segment
    /// buffered for later) or may be several segments' worth at once (a gap just closed).
    /// </summary>
    public byte[] Add(uint sequence, byte[] payload)
    {
        if (payload is null || payload.Length == 0)
        {
            return Array.Empty<byte>();
        }

        var offset = Delta(sequence, _next);

        // Entirely in the past: a retransmit of data already handed on.
        if (offset + payload.Length <= 0)
        {
            DiscardedBytes += payload.Length;
            return Array.Empty<byte>();
        }

        // Partially in the past: trim the overlap and take the new tail.
        if (offset < 0)
        {
            var skip = -offset;
            DiscardedBytes += skip;
            var trimmed = new byte[payload.Length - skip];
            Array.Copy(payload, skip, trimmed, 0, trimmed.Length);
            payload = trimmed;
            sequence = _next;
            offset = 0;
        }

        if (offset > 0)
        {
            Buffer(sequence, payload);
            return Array.Empty<byte>();
        }

        var output = new List<byte>(payload.Length);
        Consume(payload, output);
        DrainContiguous(output);
        return output.ToArray();
    }

    /// <summary>
    /// Abandons the gap the stream is waiting on and delivers the buffered segment that follows
    /// it. Call this when a connection ends, or when a gap is clearly never going to arrive.
    /// </summary>
    public byte[] SkipGap()
    {
        PurgeStale();

        // Jump to the earliest buffered segment that lies *ahead* of the stream position.
        // Never move backwards onto an already-delivered key: that would re-emit stale bytes
        // and strand the stream behind a gap the peer will never refill.
        uint? target = null;
        foreach (var key in _pending.Keys)
        {
            if (Delta(key, _next) <= 0)
            {
                continue;
            }

            if (target is null || Delta(key, target.Value) < 0)
            {
                target = key;
            }
        }

        if (target is null)
        {
            return Array.Empty<byte>();
        }

        DiscardedBytes += Delta(target.Value, _next);
        _next = target.Value;

        var output = new List<byte>();
        DrainContiguous(output);
        return output.ToArray();
    }

    /// <summary>
    /// Drops buffered segments that fell wholly at or behind the stream position — for example
    /// after a resegmented retransmit delivered a superset of their bytes. Without this they
    /// strand in the buffer forever and confuse <see cref="SkipGap"/>'s choice of target.
    /// </summary>
    private void PurgeStale()
    {
        if (_pending.Count == 0)
        {
            return;
        }

        List<uint>? stale = null;
        foreach (var (key, segment) in _pending)
        {
            if (Delta(key, _next) + segment.Length <= 0)
            {
                (stale ??= new List<uint>()).Add(key);
            }
        }

        if (stale is null)
        {
            return;
        }

        foreach (var key in stale)
        {
            _buffered -= _pending[key].Length;
            DiscardedBytes += _pending[key].Length;
            _pending.Remove(key);
        }
    }

    private void Buffer(uint sequence, byte[] payload)
    {
        if (_pending.TryGetValue(sequence, out var existing) && existing.Length >= payload.Length)
        {
            DiscardedBytes += payload.Length;
            return;
        }

        // Bytes the incoming segment would reclaim by replacing a same-key entry. The counter
        // is only adjusted once the segment is actually stored, so the refuse path below leaves
        // both _buffered and _pending untouched rather than drifting.
        var reclaimed = existing?.Length ?? 0;

        // Under memory pressure, drop the furthest-out segment: it is the least likely to be
        // the one unblocking the stream.
        while (_buffered - reclaimed + payload.Length > _maxBuffered && _pending.Count > 0)
        {
            var furthest = _pending.Keys.First();
            foreach (var key in _pending.Keys)
            {
                if (Delta(key, furthest) > 0)
                {
                    furthest = key;
                }
            }

            if (Delta(furthest, sequence) <= 0)
            {
                break;
            }

            _buffered -= _pending[furthest].Length;
            DiscardedBytes += _pending[furthest].Length;
            _pending.Remove(furthest);
        }

        if (_buffered - reclaimed + payload.Length > _maxBuffered)
        {
            DiscardedBytes += payload.Length;
            return;
        }

        _buffered += payload.Length - reclaimed;
        _pending[sequence] = payload;
    }

    private void Consume(byte[] payload, List<byte> output)
    {
        output.AddRange(payload);
        _next = unchecked(_next + (uint)payload.Length);
        DeliveredBytes += payload.Length;
    }

    private void DrainContiguous(List<byte> output)
    {
        while (true)
        {
            // Advancing _next can leave earlier buffered segments wholly behind it; clear them
            // so they cannot strand or be mistaken for a future gap.
            PurgeStale();

            if (_pending.TryGetValue(_next, out var exact))
            {
                _pending.Remove(_next);
                _buffered -= exact.Length;
                Consume(exact, output);
                continue;
            }

            // A buffered segment may start before _next and still carry new bytes.
            uint? overlapping = null;
            foreach (var key in _pending.Keys)
            {
                var delta = Delta(key, _next);
                if (delta < 0 && delta + _pending[key].Length > 0)
                {
                    overlapping = key;
                    break;
                }
            }

            if (overlapping is null)
            {
                return;
            }

            var segment = _pending[overlapping.Value];
            _pending.Remove(overlapping.Value);
            _buffered -= segment.Length;

            var skip = -Delta(overlapping.Value, _next);
            DiscardedBytes += skip;
            var tail = new byte[segment.Length - skip];
            Array.Copy(segment, skip, tail, 0, tail.Length);
            Consume(tail, output);
        }
    }

    /// <summary>
    /// Signed distance from <paramref name="b"/> to <paramref name="a"/>, correct across the
    /// 32-bit sequence-number wraparound that a long-lived connection will hit.
    /// </summary>
    internal static int Delta(uint a, uint b) => unchecked((int)(a - b));
}

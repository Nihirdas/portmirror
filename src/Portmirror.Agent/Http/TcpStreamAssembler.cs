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
        if (_pending.Count == 0)
        {
            return Array.Empty<byte>();
        }

        var earliest = _pending.Keys.First();
        foreach (var key in _pending.Keys)
        {
            if (Delta(key, earliest) < 0)
            {
                earliest = key;
            }
        }

        DiscardedBytes += Math.Max(0, Delta(earliest, _next));
        _next = earliest;

        var output = new List<byte>();
        DrainContiguous(output);
        return output.ToArray();
    }

    private void Buffer(uint sequence, byte[] payload)
    {
        if (_pending.TryGetValue(sequence, out var existing) && existing.Length >= payload.Length)
        {
            DiscardedBytes += payload.Length;
            return;
        }

        if (existing is not null)
        {
            _buffered -= existing.Length;
        }

        // Under memory pressure, drop the furthest-out segment: it is the least likely to be
        // the one unblocking the stream.
        while (_buffered + payload.Length > _maxBuffered && _pending.Count > 0)
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

        if (_buffered + payload.Length > _maxBuffered)
        {
            DiscardedBytes += payload.Length;
            return;
        }

        _pending[sequence] = payload;
        _buffered += payload.Length;
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

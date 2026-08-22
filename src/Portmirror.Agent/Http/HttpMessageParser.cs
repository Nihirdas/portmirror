using System.Globalization;
using System.Text;

namespace Portmirror.Agent.Http;

/// <summary>
/// Incremental HTTP/1.x parser. Bytes are fed in as they arrive, in any sized pieces, and
/// complete messages come out. One instance handles one direction of one connection, and keeps
/// going across a keep-alive connection carrying many messages back to back.
///
/// Deliberately lenient about what it accepts and strict about what it will consume: caps on
/// header and body size mean a hostile or merely enormous payload cannot exhaust memory, and a
/// body that hits the cap is marked truncated rather than dropped.
/// </summary>
public sealed class HttpMessageParser
{
    private enum State
    {
        StartLine,
        Headers,
        FixedLengthBody,
        ChunkSize,
        ChunkData,
        ChunkTrailingCrlf,
        Trailers,
        UntilClose
    }

    private const int DefaultMaxHeaderBytes = 64 * 1024;
    private const int DefaultMaxBodyBytes = 1024 * 1024;

    private readonly MessageKind _kind;
    private readonly int _maxHeaderBytes;
    private readonly int _maxBodyBytes;

    private readonly List<byte> _buffer = new();
    private int _consumed;

    private State _state = State.StartLine;
    private string? _method;
    private string? _target;
    private string? _version;
    private int? _status;
    private string? _reason;
    private List<KeyValuePair<string, string>> _headers = new();
    private readonly List<byte> _body = new();
    private long _remaining;
    private long _chunkRemaining;
    private bool _chunked;
    private long? _contentLength;
    private bool _truncated;
    private int _headerBytes;

    public HttpMessageParser(
        MessageKind kind,
        int maxHeaderBytes = DefaultMaxHeaderBytes,
        int maxBodyBytes = DefaultMaxBodyBytes)
    {
        _kind = kind;
        _maxHeaderBytes = maxHeaderBytes < 1024 ? 1024 : maxHeaderBytes;
        _maxBodyBytes = maxBodyBytes < 0 ? 0 : maxBodyBytes;
    }

    /// <summary>Total bytes fed in.</summary>
    public long BytesSeen { get; private set; }

    /// <summary>True when a message has been started but not yet completed.</summary>
    public bool HasPartialMessage => _state != State.StartLine || _buffer.Count > _consumed;

    /// <summary>
    /// When the next response answers a HEAD request it has no body regardless of its headers.
    /// The caller knows that; the parser cannot.
    /// </summary>
    public bool NextResponseHasNoBody { get; set; }

    /// <summary>
    /// One entry per request seen on this connection, in order, saying whether that request was
    /// a HEAD. Each final response consumes the oldest, so pipelined requests frame their
    /// responses correctly even when some are HEAD and some are not. Populated by the feed via
    /// <see cref="ExpectResponse"/>; unused when a caller drives <see cref="NextResponseHasNoBody"/>
    /// directly.
    /// </summary>
    private readonly Queue<bool> _headExpectations = new();

    /// <summary>Records, in request order, whether a request was a HEAD (its response has no body).</summary>
    public void ExpectResponse(bool headRequest) => _headExpectations.Enqueue(headRequest);

    public IReadOnlyList<ParsedMessage> Append(byte[] data) =>
        Append(data ?? Array.Empty<byte>(), 0, data?.Length ?? 0);

    public IReadOnlyList<ParsedMessage> Append(byte[] data, int offset, int count)
    {
        if (data is null || count <= 0)
        {
            return Array.Empty<ParsedMessage>();
        }

        for (var i = 0; i < count; i++)
        {
            _buffer.Add(data[offset + i]);
        }

        BytesSeen += count;

        var done = new List<ParsedMessage>();

        while (Step(done))
        {
            // Keep going while progress is being made — one Append can complete several
            // messages on a pipelined connection.
        }

        Compact();
        return done;
    }

    /// <summary>
    /// Signals that the connection closed. Completes a response whose body ran until close,
    /// and returns anything still in flight so a truncated message is reported rather than lost.
    /// </summary>
    public ParsedMessage? Finish()
    {
        if (_state == State.UntilClose)
        {
            return Complete();
        }

        if (_state is State.FixedLengthBody or State.ChunkData or State.ChunkSize
            or State.ChunkTrailingCrlf or State.Trailers)
        {
            _truncated = true;
            return Complete();
        }

        return null;
    }

    /// <summary>
    /// Abandons the message in flight because the captured stream lost bytes it needed and can
    /// never get back. The bytes fed next begin somewhere mid-stream, so this realigns to the
    /// next start line they contain — rather than mistaking them for the lost message's body,
    /// which is exactly what would happen while the parser sat waiting in a body state. Any
    /// half-built message, any buffered scraps, and any pending HEAD expectations are dropped,
    /// since after a gap the request/response correspondence can no longer be trusted.
    /// Returns true if a partial message was actually discarded.
    /// </summary>
    public bool ResyncAfterGap()
    {
        var hadPartial = HasPartialMessage;

        Reset();
        _buffer.Clear();
        _consumed = 0;
        _headExpectations.Clear();

        return hadPartial;
    }

    private bool Step(List<ParsedMessage> done)
    {
        switch (_state)
        {
            case State.StartLine:
            {
                var line = TryReadLine();
                if (line is null)
                {
                    return false;
                }

                if (line.Length == 0)
                {
                    // Stray CRLF between messages is legal and ignorable.
                    return true;
                }

                if (!ParseStartLine(line))
                {
                    // Captured streams lose segments, so a start line is sometimes the tail of
                    // one message glued to the head of the next. Scan forward for the next
                    // plausible message rather than reading the wreckage line by line.
                    Resynchronise();
                    return true;
                }

                _state = State.Headers;
                return true;
            }

            case State.Headers:
            {
                var line = TryReadLine();
                if (line is null)
                {
                    return false;
                }

                _headerBytes += line.Length + 2;

                if (_headerBytes > _maxHeaderBytes)
                {
                    Reset();
                    return true;
                }

                if (line.Length > 0)
                {
                    AddHeader(line);
                    return true;
                }

                // A message with no body completes the moment the headers end.
                var immediate = BeginBody();
                if (immediate is not null)
                {
                    done.Add(immediate);
                }

                return true;
            }

            case State.FixedLengthBody:
            {
                var available = _buffer.Count - _consumed;
                if (available == 0)
                {
                    return false;
                }

                var take = (int)Math.Min(available, _remaining);
                AppendBody(take);
                _remaining -= take;

                if (_remaining == 0)
                {
                    done.Add(Complete());
                }

                return true;
            }

            case State.ChunkSize:
            {
                var line = TryReadLine();
                if (line is null)
                {
                    return false;
                }

                var text = line;
                var semi = text.IndexOf(';');
                if (semi >= 0)
                {
                    text = text[..semi];
                }

                text = text.Trim();

                if (text.Length == 0)
                {
                    return true;
                }

                if (!long.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var size)
                    || size < 0)
                {
                    _truncated = true;
                    done.Add(Complete());
                    return true;
                }

                if (size == 0)
                {
                    _state = State.Trailers;
                    return true;
                }

                _chunkRemaining = size;
                _state = State.ChunkData;
                return true;
            }

            case State.ChunkData:
            {
                var available = _buffer.Count - _consumed;
                if (available == 0)
                {
                    return false;
                }

                var take = (int)Math.Min(available, _chunkRemaining);
                AppendBody(take);
                _chunkRemaining -= take;

                if (_chunkRemaining == 0)
                {
                    _state = State.ChunkTrailingCrlf;
                }

                return true;
            }

            case State.ChunkTrailingCrlf:
            {
                var line = TryReadLine();
                if (line is null)
                {
                    return false;
                }

                _state = State.ChunkSize;
                return true;
            }

            case State.Trailers:
            {
                var line = TryReadLine();
                if (line is null)
                {
                    return false;
                }

                if (line.Length == 0)
                {
                    done.Add(Complete());
                    return true;
                }

                // Trailers count against the same budget as headers; a flood of trailer lines
                // must not grow the header list without bound. The body is already complete, so
                // on overflow just finish the message with the trailers seen so far.
                _headerBytes += line.Length + 2;
                if (_headerBytes > _maxHeaderBytes)
                {
                    done.Add(Complete());
                    return true;
                }

                AddHeader(line);
                return true;
            }

            case State.UntilClose:
            {
                var available = _buffer.Count - _consumed;
                if (available == 0)
                {
                    return false;
                }

                AppendBody(available);
                return true;
            }

            default:
                return false;
        }
    }

    private bool ParseStartLine(string line)
    {
        if (_kind == MessageKind.Response)
        {
            if (!line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var parts = line.Split(' ', 3);
            if (parts.Length < 2 || !int.TryParse(parts[1], out var code))
            {
                return false;
            }

            _version = parts[0];
            _status = code;
            _reason = parts.Length > 2 ? parts[2] : string.Empty;
            return true;
        }

        var bits = line.Split(' ');
        if (bits.Length != 3 || !bits[2].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        _method = bits[0];
        _target = bits[1];
        _version = bits[2];
        return true;
    }

    private ParsedMessage? BeginBody()
    {
        var transferEncoding = FindHeader("Transfer-Encoding");
        _chunked = transferEncoding is not null
                   && transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase);

        var lengthHeader = FindHeader("Content-Length");
        _contentLength = long.TryParse(lengthHeader, out var len) && len >= 0 ? len : null;

        if (_kind == MessageKind.Response && ResponseCannotHaveBody())
        {
            return Complete();
        }

        if (_chunked)
        {
            _state = State.ChunkSize;
            return null;
        }

        if (_contentLength.HasValue)
        {
            if (_contentLength.Value == 0)
            {
                return Complete();
            }

            _remaining = _contentLength.Value;
            _state = State.FixedLengthBody;
            return null;
        }

        // A request without a length has no body. A response without one runs until close.
        if (_kind == MessageKind.Response)
        {
            _state = State.UntilClose;
            return null;
        }

        return Complete();
    }

    private bool ResponseCannotHaveBody()
    {
        var code = _status ?? 0;

        // A 1xx interim response never carries a body and is not the answer to the pending
        // request, so it must not consume a HEAD expectation.
        if (code >= 100 && code < 200)
        {
            return true;
        }

        // This is the final response: it answers the oldest outstanding request, so consume that
        // request's HEAD marker (if the feed queued one) in order.
        var headExpected = _headExpectations.Count > 0 && _headExpectations.Dequeue();

        return NextResponseHasNoBody || headExpected || code is 204 or 304;
    }

    private ParsedMessage Complete()
    {
        var message = new ParsedMessage
        {
            Kind = _kind,
            Method = _method,
            Target = _target,
            StatusCode = _status,
            ReasonPhrase = _reason,
            Version = _version,
            Headers = _headers,
            Chunked = _chunked,
            ContentLength = _contentLength,
            Body = _body.ToArray(),
            BodyTruncated = _truncated
        };

        BodyDecoder.Decode(message);

        // A 1xx interim response (100 Continue, 103 Early Hints) carries no body and is
        // followed by the real response. The caller's "this is the answer to a HEAD" flag
        // applies to that final response, so it must survive the interim one's reset.
        var carryHeadFlag = _kind == MessageKind.Response
            && _status is >= 100 and < 200
            && NextResponseHasNoBody;

        Reset();

        if (carryHeadFlag)
        {
            NextResponseHasNoBody = true;
        }

        return message;
    }

    private void Reset()
    {
        _state = State.StartLine;
        _method = _target = _version = _reason = null;
        _status = null;
        _headers = new List<KeyValuePair<string, string>>();
        _body.Clear();
        _remaining = 0;
        _chunkRemaining = 0;
        _chunked = false;
        _contentLength = null;
        _truncated = false;
        _headerBytes = 0;
        NextResponseHasNoBody = false;
    }

    private void AppendBody(int count)
    {
        for (var i = 0; i < count; i++)
        {
            if (_body.Count < _maxBodyBytes)
            {
                _body.Add(_buffer[_consumed + i]);
            }
            else
            {
                _truncated = true;
            }
        }

        _consumed += count;
    }

    private void AddHeader(string line)
    {
        // Obsolete line folding: a leading space continues the previous header.
        if ((line[0] == ' ' || line[0] == '\t') && _headers.Count > 0)
        {
            var last = _headers[^1];
            _headers[^1] = new KeyValuePair<string, string>(last.Key, last.Value + " " + line.Trim());
            return;
        }

        var colon = line.IndexOf(':');
        if (colon <= 0)
        {
            return;
        }

        _headers.Add(new KeyValuePair<string, string>(
            line[..colon].Trim(), line[(colon + 1)..].Trim()));
    }

    private string? FindHeader(string name)
    {
        foreach (var h in _headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value;
            }
        }

        return null;
    }

    private static readonly string[] Methods =
    {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "
    };

    /// <summary>
    /// Skips to the next byte offset that plausibly begins a message. Always moves strictly
    /// forward, so a stream full of noise cannot spin here.
    /// </summary>
    private void Resynchronise()
    {
        for (var i = _consumed; i < _buffer.Count; i++)
        {
            if (LooksLikeMessageStart(i))
            {
                _consumed = i;
                return;
            }
        }

        // Nothing plausible in what we hold. Drop it, but keep a short tail in case a marker
        // straddles the boundary and the rest of it is still in flight.
        var keep = Math.Min(_buffer.Count - _consumed, 9);
        _consumed = _buffer.Count - keep;
    }

    private bool LooksLikeMessageStart(int index)
    {
        if (_kind == MessageKind.Response)
        {
            return MatchesAt(index, "HTTP/1.");
        }

        foreach (var method in Methods)
        {
            if (MatchesAt(index, method))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesAt(int index, string token)
    {
        if (index + token.Length > _buffer.Count)
        {
            return false;
        }

        for (var i = 0; i < token.Length; i++)
        {
            if (_buffer[index + i] != (byte)token[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Reads one CRLF- or LF-terminated line, or null if one is not complete yet.</summary>
    private string? TryReadLine()
    {
        for (var i = _consumed; i < _buffer.Count; i++)
        {
            if (_buffer[i] != (byte)'\n')
            {
                continue;
            }

            var end = i;
            if (end > _consumed && _buffer[end - 1] == (byte)'\r')
            {
                end--;
            }

            var length = end - _consumed;
            var bytes = new byte[length];
            for (var j = 0; j < length; j++)
            {
                bytes[j] = _buffer[_consumed + j];
            }

            _consumed = i + 1;
            return Encoding.Latin1.GetString(bytes);
        }

        return null;
    }

    /// <summary>Drops already-consumed bytes so a long-lived connection does not grow forever.</summary>
    private void Compact()
    {
        if (_consumed == 0)
        {
            return;
        }

        _buffer.RemoveRange(0, _consumed);
        _consumed = 0;
    }
}

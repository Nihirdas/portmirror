using System.Text.Json.Serialization;

namespace Portmirror.Agent.Capture;

/// <summary>How a given exchange was observed. Determines how much detail is present.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CaptureTier
{
    /// <summary>HTTP.SYS ETW. Complete inbound coverage including loopback, but no bodies.</summary>
    EtwMetadata,

    /// <summary>Packet capture off the wire. Carries bodies, but cannot see same-host traffic.</summary>
    PacketCapture,

    /// <summary>In-process IIS module. Complete, with bodies, and can alter the response.</summary>
    IisModule
}

/// <summary>Whether the local host received the request (inbound) or made it (outbound).</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CaptureDirection
{
    /// <summary>Direction could not be determined (e.g. neither endpoint is the local host).</summary>
    Unknown,

    /// <summary>A request served by the local host — someone called in.</summary>
    Inbound,

    /// <summary>A request the local host made to another server — a server-to-server call out.</summary>
    Outbound
}

/// <summary>One half of an exchange: headers plus an optional body.</summary>
public sealed class HttpMessage
{
    public Dictionary<string, string> Headers { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public string? ContentType { get; set; }
    public long? ContentLength { get; set; }

    /// <summary>The body as readable text, after decompression and redaction. Null when the body
    /// was empty or is binary — see <see cref="BodyFormat"/> and <see cref="BodyByteCount"/>.</summary>
    public string? Body { get; set; }

    /// <summary>One of empty / json / xml / text / binary. Tells a client whether to offer a
    /// pretty-print toggle, and whether a body exists at all.</summary>
    public string BodyFormat { get; set; } = "empty";

    /// <summary>Size of the body as captured on the wire (post-decompression), in bytes.</summary>
    public long BodyByteCount { get; set; }

    public bool BodyRedacted { get; set; }
    public bool BodyTruncated { get; set; }

    /// <summary>Set when a Content-Encoding was present but could not be decompressed.</summary>
    public string? DecodeError { get; set; }
}

/// <summary>
/// A single request/response pair. Body-bearing fields stay null under
/// <see cref="CaptureTier.EtwMetadata"/> so higher tiers slot in without an API change.
/// </summary>
public sealed class Exchange
{
    /// <summary>Monotonic sequence assigned on insertion into the ring. Drives incremental polling.</summary>
    public long Seq { get; set; }

    public string Id { get; init; } = Guid.NewGuid().ToString("n");
    public string CorrelationId { get; init; } = string.Empty;

    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset? CompletedUtc { get; set; }
    public double? DurationMs { get; set; }

    public string? Verb { get; set; }
    public string? Url { get; set; }
    public int? StatusCode { get; set; }
    public string? ClientIp { get; set; }
    public string? SiteId { get; set; }
    public string? QueueName { get; set; }

    public CaptureTier Tier { get; set; } = CaptureTier.EtwMetadata;

    /// <summary>Inbound (served here) or outbound (a server-to-server call this host made).</summary>
    public CaptureDirection Direction { get; set; } = CaptureDirection.Unknown;

    /// <summary>True when the exchange was flushed on idle timeout rather than seeing a terminal event.</summary>
    public bool Partial { get; set; }

    public HttpMessage? Request { get; set; }
    public HttpMessage? Response { get; set; }
}

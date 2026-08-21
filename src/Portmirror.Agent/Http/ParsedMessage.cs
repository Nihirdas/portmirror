namespace Portmirror.Agent.Http;

public enum MessageKind
{
    Request,
    Response
}

/// <summary>One complete HTTP message recovered from a byte stream.</summary>
public sealed class ParsedMessage
{
    public MessageKind Kind { get; init; }

    // Request line.
    public string? Method { get; init; }
    public string? Target { get; init; }

    // Status line.
    public int? StatusCode { get; init; }
    public string? ReasonPhrase { get; init; }

    public string? Version { get; init; }

    public List<KeyValuePair<string, string>> Headers { get; init; } = new();

    /// <summary>Body as it appeared on the wire, after any content-encoding was undone.</summary>
    public byte[] Body { get; set; } = Array.Empty<byte>();

    /// <summary>True when the body hit the configured cap and was cut short.</summary>
    public bool BodyTruncated { get; set; }

    /// <summary>True when a Content-Encoding was successfully decompressed.</summary>
    public bool BodyDecompressed { get; set; }

    /// <summary>Set when a Content-Encoding was present but could not be decompressed.</summary>
    public string? DecodeError { get; set; }

    public bool Chunked { get; init; }
    public long? ContentLength { get; init; }

    public string? Header(string name)
    {
        foreach (var h in Headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return h.Value;
            }
        }

        return null;
    }

    public string? ContentType => Header("Content-Type");
}

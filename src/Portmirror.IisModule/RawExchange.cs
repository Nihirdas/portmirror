using System;
using System.Collections.Generic;

namespace Portmirror.IisModule;

/// <summary>
/// Raw captured data, gathered on the request thread with no transformation. Decompression,
/// redaction and mapping happen later, off the request thread, so the hot path only copies bytes.
/// </summary>
public sealed class RawExchange
{
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset CompletedUtc { get; set; }
    public string? Verb { get; set; }
    public string? RawUrl { get; set; }
    public int StatusCode { get; set; }
    public string? ClientIp { get; set; }

    public List<KeyValuePair<string, string>> RequestHeaders { get; set; } = new();
    public byte[] RequestBody { get; set; } = Array.Empty<byte>();
    public bool RequestTruncated { get; set; }

    public List<KeyValuePair<string, string>> ResponseHeaders { get; set; } = new();
    public byte[] ResponseBody { get; set; } = Array.Empty<byte>();
    public bool ResponseTruncated { get; set; }
}

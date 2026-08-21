using System.Net;

namespace Portmirror.Agent.Pcap;

/// <summary>One endpoint of a TCP connection: an address and a port.</summary>
public readonly record struct Endpoint(IPAddress Address, int Port)
{
    public override string ToString() =>
        Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{Address}]:{Port}"
            : $"{Address}:{Port}";
}

/// <summary>
/// A single TCP segment carved out of a captured packet: who sent it, its sequence number,
/// the control flags that matter for connection tracking, and its payload bytes.
/// </summary>
public sealed class TcpSegment
{
    public required Endpoint Source { get; init; }
    public required Endpoint Destination { get; init; }
    public uint Sequence { get; init; }
    public bool Syn { get; init; }
    public bool Ack { get; init; }
    public bool Fin { get; init; }
    public bool Rst { get; init; }
    public byte[] Payload { get; init; } = Array.Empty<byte>();
    public long TimestampTicks { get; init; }
}

/// <summary>
/// Direction-independent identity of a connection: the same value for both directions, so the
/// two halves of a conversation reassemble into one flow. Built by ordering the two endpoints
/// deterministically.
/// </summary>
public readonly struct FlowKey : IEquatable<FlowKey>
{
    private readonly string _key;

    private FlowKey(string key) => _key = key;

    public static FlowKey For(Endpoint a, Endpoint b)
    {
        var sa = a.ToString();
        var sb = b.ToString();
        // Order the pair so (a,b) and (b,a) collapse to one key.
        return string.CompareOrdinal(sa, sb) <= 0
            ? new FlowKey(sa + "|" + sb)
            : new FlowKey(sb + "|" + sa);
    }

    public bool Equals(FlowKey other) => _key == other._key;
    public override bool Equals(object? obj) => obj is FlowKey f && Equals(f);
    public override int GetHashCode() => _key.GetHashCode(StringComparison.Ordinal);
    public override string ToString() => _key;
}

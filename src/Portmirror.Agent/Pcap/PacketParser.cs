using System.Buffers.Binary;
using System.Net;

namespace Portmirror.Agent.Pcap;

/// <summary>
/// Peels a captured frame down to its TCP segment: Ethernet (with VLAN tags) or raw IP, then
/// IPv4 or IPv6, then TCP. Returns null for anything that is not TCP-over-IP, or for a frame
/// too truncated to trust — a capture tool must never invent bytes it did not see.
/// </summary>
public static class PacketParser
{
    // pcapng / libpcap link types.
    public const int LinkTypeEthernet = 1;
    public const int LinkTypeRawIp = 101;   // LINKTYPE_RAW: bare IP, no link layer
    public const int LinkTypeNull = 0;      // BSD loopback: 4-byte family header

    private const ushort EtherTypeIpv4 = 0x0800;
    private const ushort EtherTypeIpv6 = 0x86DD;
    private const ushort EtherTypeVlan = 0x8100;
    private const ushort EtherTypeVlanQinQ = 0x88A8;

    private const byte ProtocolTcp = 6;

    public static TcpSegment? Parse(int linkType, ReadOnlySpan<byte> frame, long timestampTicks = 0)
    {
        var ip = linkType switch
        {
            LinkTypeEthernet => StripEthernet(frame),
            LinkTypeRawIp => frame,
            LinkTypeNull => frame.Length >= 4 ? frame[4..] : default,
            _ => default
        };

        if (ip.IsEmpty)
        {
            return null;
        }

        return ParseIp(ip, timestampTicks);
    }

    private static ReadOnlySpan<byte> StripEthernet(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14)
        {
            return default;
        }

        var etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[12..]);
        var offset = 14;

        // Walk past any stacked VLAN tags.
        while (etherType is EtherTypeVlan or EtherTypeVlanQinQ)
        {
            if (frame.Length < offset + 4)
            {
                return default;
            }

            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[(offset + 2)..]);
            offset += 4;
        }

        return etherType is EtherTypeIpv4 or EtherTypeIpv6 ? frame[offset..] : default;
    }

    private static TcpSegment? ParseIp(ReadOnlySpan<byte> ip, long timestampTicks)
    {
        if (ip.IsEmpty)
        {
            return null;
        }

        var version = ip[0] >> 4;
        return version switch
        {
            4 => ParseIpv4(ip, timestampTicks),
            6 => ParseIpv6(ip, timestampTicks),
            _ => null
        };
    }

    private static TcpSegment? ParseIpv4(ReadOnlySpan<byte> ip, long timestampTicks)
    {
        if (ip.Length < 20)
        {
            return null;
        }

        var ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || ip.Length < ihl)
        {
            return null;
        }

        if (ip[9] != ProtocolTcp)
        {
            return null;
        }

        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);

        // Trust the smaller of declared total length and what was actually captured, so a
        // truncated capture never reads past the buffer and trailing padding is excluded.
        var end = Math.Min((int)totalLength, ip.Length);
        if (end < ihl)
        {
            return null;
        }

        var src = new IPAddress(ip.Slice(12, 4).ToArray());
        var dst = new IPAddress(ip.Slice(16, 4).ToArray());

        return ParseTcp(ip[ihl..end], src, dst, timestampTicks);
    }

    private static TcpSegment? ParseIpv6(ReadOnlySpan<byte> ip, long timestampTicks)
    {
        if (ip.Length < 40)
        {
            return null;
        }

        // Only the common no-extension-header case; TCP must be the immediate next header.
        if (ip[6] != ProtocolTcp)
        {
            return null;
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(ip[4..]);
        var end = Math.Min(40 + payloadLength, ip.Length);
        if (end < 40)
        {
            return null;
        }

        var src = new IPAddress(ip.Slice(8, 16).ToArray());
        var dst = new IPAddress(ip.Slice(24, 16).ToArray());

        return ParseTcp(ip[40..end], src, dst, timestampTicks);
    }

    private static TcpSegment? ParseTcp(
        ReadOnlySpan<byte> tcp, IPAddress srcIp, IPAddress dstIp, long timestampTicks)
    {
        if (tcp.Length < 20)
        {
            return null;
        }

        var dataOffset = (tcp[12] >> 4) * 4;
        if (dataOffset < 20 || tcp.Length < dataOffset)
        {
            return null;
        }

        var srcPort = BinaryPrimitives.ReadUInt16BigEndian(tcp[0..]);
        var dstPort = BinaryPrimitives.ReadUInt16BigEndian(tcp[2..]);
        var seq = BinaryPrimitives.ReadUInt32BigEndian(tcp[4..]);
        var flags = tcp[13];

        return new TcpSegment
        {
            Source = new Endpoint(srcIp, srcPort),
            Destination = new Endpoint(dstIp, dstPort),
            Sequence = seq,
            Fin = (flags & 0x01) != 0,
            Syn = (flags & 0x02) != 0,
            Rst = (flags & 0x04) != 0,
            Ack = (flags & 0x10) != 0,
            Payload = tcp[dataOffset..].ToArray(),
            TimestampTicks = timestampTicks
        };
    }
}

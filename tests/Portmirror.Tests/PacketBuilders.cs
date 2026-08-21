using System.Buffers.Binary;
using System.Net;

namespace Portmirror.Tests;

/// <summary>Hand-builds Ethernet/IP/TCP frames and pcapng files so the parsers can be tested off real bytes.</summary>
internal static class PacketBuilders
{
    public static byte[] Ethernet(ushort etherType, byte[] payload, bool vlan = false)
    {
        var vlanTag = vlan ? 4 : 0;
        var frame = new byte[14 + vlanTag + payload.Length];
        // dst + src MAC left as zeros
        var typePos = 12;
        if (vlan)
        {
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), 0x8100);
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(14), 0x0000);   // VLAN TCI
            typePos = 16;
        }
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(typePos), etherType);
        payload.CopyTo(frame, typePos + 2);
        return frame;
    }

    public static byte[] Ipv4Tcp(
        string srcIp, int srcPort, string dstIp, int dstPort, uint seq, byte[] payload,
        bool syn = false, bool ack = false, bool fin = false, int trailingPad = 0)
    {
        var tcp = Tcp(srcPort, dstPort, seq, payload, syn, ack, fin);
        var total = 20 + tcp.Length;
        var ip = new byte[total + trailingPad];
        ip[0] = 0x45;                                            // version 4, IHL 5
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)total);
        ip[9] = 6;                                               // protocol TCP
        IPAddress.Parse(srcIp).GetAddressBytes().CopyTo(ip, 12);
        IPAddress.Parse(dstIp).GetAddressBytes().CopyTo(ip, 16);
        tcp.CopyTo(ip, 20);
        return ip;
    }

    public static byte[] Ipv6Tcp(
        string srcIp, int srcPort, string dstIp, int dstPort, uint seq, byte[] payload)
    {
        var tcp = Tcp(srcPort, dstPort, seq, payload, false, true, false);
        var ip = new byte[40 + tcp.Length];
        ip[0] = 0x60;                                            // version 6
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(4), (ushort)tcp.Length);
        ip[6] = 6;                                               // next header TCP
        IPAddress.Parse(srcIp).GetAddressBytes().CopyTo(ip, 8);
        IPAddress.Parse(dstIp).GetAddressBytes().CopyTo(ip, 24);
        tcp.CopyTo(ip, 40);
        return ip;
    }

    public static byte[] Ipv4Udp(string srcIp, string dstIp)
    {
        var ip = new byte[28];
        ip[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), 28);
        ip[9] = 17;                                              // UDP
        IPAddress.Parse(srcIp).GetAddressBytes().CopyTo(ip, 12);
        IPAddress.Parse(dstIp).GetAddressBytes().CopyTo(ip, 16);
        return ip;
    }

    private static byte[] Tcp(int srcPort, int dstPort, uint seq, byte[] payload, bool syn, bool ack, bool fin)
    {
        var tcp = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0), (ushort)srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), (ushort)dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4), seq);
        tcp[12] = 5 << 4;                                        // data offset 5 words = 20 bytes
        byte flags = 0;
        if (fin) flags |= 0x01;
        if (syn) flags |= 0x02;
        if (ack) flags |= 0x10;
        tcp[13] = flags;
        payload.CopyTo(tcp, 20);
        return tcp;
    }

    // ---- pcapng container ----

    public static byte[] Pcapng(int linkType, IEnumerable<byte[]> frames, bool littleEndian = true)
    {
        var blocks = new List<byte[]>
        {
            SectionHeader(littleEndian),
            InterfaceDescription(linkType, littleEndian)
        };
        foreach (var f in frames)
        {
            blocks.Add(EnhancedPacket(f, littleEndian));
        }
        return blocks.SelectMany(b => b).ToArray();
    }

    private static byte[] SectionHeader(bool le)
    {
        var body = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(0), 0x1A2B3C4D);   // magic (as written)
        if (!le) { Array.Reverse(body, 0, 4); }
        // major/minor 1.0 and section length -1 left as-is (endianness immaterial for the test)
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(4), 1);
        for (var i = 8; i < 16; i++) { body[i] = 0xFF; }
        return Block(0x0A0D0D0A, body, le);
    }

    private static byte[] InterfaceDescription(int linkType, bool le)
    {
        var body = new byte[8];
        Write16(body, 0, (ushort)linkType, le);
        Write32(body, 4, 0xFFFF, le);   // snaplen
        return Block(0x00000001, body, le);
    }

    private static byte[] EnhancedPacket(byte[] data, bool le)
    {
        var padded = (data.Length + 3) & ~3;
        var body = new byte[20 + padded];
        Write32(body, 0, 0, le);                    // interface id
        Write32(body, 4, 0, le);                    // ts high
        Write32(body, 8, 0x12345678, le);           // ts low
        Write32(body, 12, (uint)data.Length, le);   // captured length
        Write32(body, 16, (uint)data.Length, le);   // original length
        data.CopyTo(body, 20);
        return Block(0x00000006, body, le);
    }

    private static byte[] Block(uint type, byte[] body, bool le)
    {
        var total = 12 + body.Length;
        var block = new byte[total];
        Write32(block, 0, type, le);
        Write32(block, 4, (uint)total, le);
        body.CopyTo(block, 8);
        Write32(block, total - 4, (uint)total, le);
        return block;
    }

    private static void Write32(byte[] b, int o, uint v, bool le)
    {
        if (le) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o), v);
        else BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o), v);
    }

    private static void Write16(byte[] b, int o, ushort v, bool le)
    {
        if (le) BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(o), v);
        else BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o), v);
    }
}

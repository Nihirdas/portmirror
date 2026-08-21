using System.Buffers.Binary;

namespace Portmirror.Agent.Pcap;

/// <summary>A packet lifted out of a pcapng file: its link type, its bytes, and when it was seen.</summary>
public sealed class CapturedPacket
{
    public required int LinkType { get; init; }
    public required byte[] Data { get; init; }
    public long TimestampTicks { get; init; }
}

/// <summary>
/// Reads the pcapng container that pktmon's etl2pcap produces. Handles both byte orders, the
/// blocks that carry packets (Enhanced and Simple Packet Blocks), and maps each packet to the
/// link type of its interface. Unknown block types are skipped by their length, so a file with
/// options or vendor blocks still yields its packets.
/// </summary>
public static class PcapngReader
{
    private const uint BlockSectionHeader = 0x0A0D0D0A;
    private const uint BlockInterfaceDescription = 0x00000001;
    private const uint BlockSimplePacket = 0x00000003;
    private const uint BlockEnhancedPacket = 0x00000006;
    private const uint ByteOrderMagic = 0x1A2B3C4D;

    public static IReadOnlyList<CapturedPacket> Read(byte[] file)
    {
        ArgumentNullException.ThrowIfNull(file);

        var packets = new List<CapturedPacket>();
        var interfaces = new List<int>();   // interface id -> link type, in declaration order
        var littleEndian = true;
        var pos = 0;

        while (pos + 12 <= file.Length)
        {
            // The Section Header Block's type is byte-order independent, so reading it with the
            // default endianness always identifies it; every later block type must be read with
            // the endianness that header established.
            var blockType = ReadU32(file, pos, littleEndian);

            if (blockType == BlockSectionHeader)
            {
                // The section header's own byte order sets the endianness for the section.
                var magic = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(pos + 8));
                littleEndian = magic == ByteOrderMagic;
                interfaces.Clear();
            }

            var totalLength = ReadU32(file, pos + 4, littleEndian);

            // A block is at least its 12 bytes of framing and is 32-bit aligned; anything else
            // is a corrupt file, so stop rather than loop forever. The comparison is done in
            // long so a length with the high bit set cannot cast to a negative int and slip past.
            if (totalLength < 12 || totalLength % 4 != 0 || (long)pos + totalLength > file.Length)
            {
                break;
            }

            // Safe now: totalLength <= file.Length - pos, so it fits in a positive int.
            var blockLength = (int)totalLength;
            var bodyStart = pos + 8;
            var bodyEnd = pos + blockLength - 4;   // trailing redundant length

            switch (blockType)
            {
                case BlockInterfaceDescription:
                    // pcapng assigns interface ids by declaration order, so a malformed IDB must
                    // still occupy a slot or every later packet's link type shifts.
                    interfaces.Add(bodyEnd - bodyStart >= 2
                        ? ReadU16(file, bodyStart, littleEndian)
                        : PacketParser.LinkTypeEthernet);
                    break;

                case BlockEnhancedPacket:
                    ReadEnhancedPacket(file, bodyStart, bodyEnd, littleEndian, interfaces, packets);
                    break;

                case BlockSimplePacket:
                    ReadSimplePacket(file, bodyStart, bodyEnd, littleEndian, interfaces, packets);
                    break;
            }

            pos += blockLength;
        }

        return packets;
    }

    private static void ReadEnhancedPacket(
        byte[] file, int bodyStart, int bodyEnd, bool le, List<int> interfaces, List<CapturedPacket> packets)
    {
        if (bodyEnd - bodyStart < 20)
        {
            return;
        }

        var interfaceId = (int)ReadU32(file, bodyStart, le);
        var tsHigh = ReadU32(file, bodyStart + 4, le);
        var tsLow = ReadU32(file, bodyStart + 8, le);
        var captured = ReadU32(file, bodyStart + 12, le);   // uint; may be attacker-controlled

        var dataStart = bodyStart + 20;

        // Compare in long: a large captured value must not overflow int and slip past the bound.
        if ((long)dataStart + captured > bodyEnd)
        {
            return;
        }

        packets.Add(new CapturedPacket
        {
            LinkType = LinkTypeFor(interfaces, interfaceId),
            Data = file.AsSpan(dataStart, (int)captured).ToArray(),
            TimestampTicks = (long)(((ulong)tsHigh << 32) | tsLow)
        });
    }

    private static void ReadSimplePacket(
        byte[] file, int bodyStart, int bodyEnd, bool le, List<int> interfaces, List<CapturedPacket> packets)
    {
        if (bodyEnd - bodyStart < 4)
        {
            return;
        }

        var originalLength = ReadU32(file, bodyStart, le);   // uint
        var dataStart = bodyStart + 4;

        // A simple packet block has no captured-length field of its own; it is bounded by the
        // block, and uses interface 0. Cap in long so a huge length cannot over-read.
        var available = bodyEnd - dataStart;
        var length = (int)Math.Min(originalLength, (uint)Math.Max(0, available));
        if (length <= 0)
        {
            return;
        }

        packets.Add(new CapturedPacket
        {
            LinkType = LinkTypeFor(interfaces, 0),
            Data = file.AsSpan(dataStart, length).ToArray(),
            TimestampTicks = 0
        });
    }

    private static int LinkTypeFor(List<int> interfaces, int interfaceId) =>
        interfaceId >= 0 && interfaceId < interfaces.Count
            ? interfaces[interfaceId]
            : PacketParser.LinkTypeEthernet;   // sensible default when no IDB was seen

    private static uint ReadU32(byte[] b, int offset, bool le) =>
        le ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(offset))
           : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(offset));

    private static ushort ReadU16(byte[] b, int offset, bool le) =>
        le ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(offset))
           : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(offset));
}

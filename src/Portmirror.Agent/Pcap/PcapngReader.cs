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
            var blockType = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(pos));

            if (blockType == BlockSectionHeader)
            {
                // The section header's own byte order sets the endianness for the section.
                var magic = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(pos + 8));
                littleEndian = magic == ByteOrderMagic;
                interfaces.Clear();
            }

            var totalLength = ReadU32(file, pos + 4, littleEndian);

            // A block is at least its 12 bytes of framing and is 32-bit aligned; anything else
            // is a corrupt file, so stop rather than loop forever.
            if (totalLength < 12 || totalLength % 4 != 0 || pos + (int)totalLength > file.Length)
            {
                break;
            }

            var bodyStart = pos + 8;
            var bodyEnd = pos + (int)totalLength - 4;   // trailing redundant length

            switch (blockType)
            {
                case BlockInterfaceDescription:
                    if (bodyEnd - bodyStart >= 2)
                    {
                        interfaces.Add(ReadU16(file, bodyStart, littleEndian));
                    }
                    break;

                case BlockEnhancedPacket:
                    ReadEnhancedPacket(file, bodyStart, bodyEnd, littleEndian, interfaces, packets);
                    break;

                case BlockSimplePacket:
                    ReadSimplePacket(file, bodyStart, bodyEnd, littleEndian, interfaces, packets);
                    break;
            }

            pos += (int)totalLength;
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
        var captured = (int)ReadU32(file, bodyStart + 12, le);

        var dataStart = bodyStart + 20;
        if (captured < 0 || dataStart + captured > bodyEnd)
        {
            return;
        }

        packets.Add(new CapturedPacket
        {
            LinkType = LinkTypeFor(interfaces, interfaceId),
            Data = file.AsSpan(dataStart, captured).ToArray(),
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

        var originalLength = (int)ReadU32(file, bodyStart, le);
        var dataStart = bodyStart + 4;

        // A simple packet block has no captured-length field of its own; it is bounded by the
        // block, and uses interface 0.
        var available = bodyEnd - dataStart;
        var length = Math.Min(originalLength, available);
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

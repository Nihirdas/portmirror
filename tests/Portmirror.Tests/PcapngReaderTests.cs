using System.Buffers.Binary;
using System.Text;
using Portmirror.Agent.Pcap;
using Xunit;

namespace Portmirror.Tests;

public class PcapngReaderTests
{
    private static byte[] SampleFrame(string payload)
    {
        var ip = PacketBuilders.Ipv4Tcp("10.0.0.1", 5, "10.0.0.2", 80, 1, Encoding.ASCII.GetBytes(payload));
        return PacketBuilders.Ethernet(0x0800, ip);
    }

    [Fact]
    public void Reads_a_single_packet_little_endian()
    {
        var file = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[] { SampleFrame("hello") });

        var packets = PcapngReader.Read(file);

        var p = Assert.Single(packets);
        Assert.Equal(PacketParser.LinkTypeEthernet, p.LinkType);
        var seg = PacketParser.Parse(p.LinkType, p.Data);
        Assert.Equal("hello", Encoding.ASCII.GetString(seg!.Payload));
    }

    [Fact]
    public void Reads_packets_big_endian()
    {
        var file = PacketBuilders.Pcapng(
            PacketParser.LinkTypeEthernet, new[] { SampleFrame("BE") }, littleEndian: false);

        var p = Assert.Single(PcapngReader.Read(file));
        var seg = PacketParser.Parse(p.LinkType, p.Data);
        Assert.Equal("BE", Encoding.ASCII.GetString(seg!.Payload));
    }

    [Fact]
    public void Reads_several_packets_in_order()
    {
        var file = PacketBuilders.Pcapng(
            PacketParser.LinkTypeEthernet,
            new[] { SampleFrame("one"), SampleFrame("two"), SampleFrame("three") });

        var packets = PcapngReader.Read(file);

        Assert.Equal(3, packets.Count);
        Assert.Equal("one", Payload(packets[0]));
        Assert.Equal("three", Payload(packets[2]));
    }

    [Fact]
    public void Carries_the_interface_link_type_to_each_packet()
    {
        var file = PacketBuilders.Pcapng(PacketParser.LinkTypeRawIp,
            new[] { PacketBuilders.Ipv4Tcp("10.0.0.1", 5, "10.0.0.2", 80, 1, Encoding.ASCII.GetBytes("raw")) });

        var p = Assert.Single(PcapngReader.Read(file));
        Assert.Equal(PacketParser.LinkTypeRawIp, p.LinkType);
    }

    [Fact]
    public void A_truncated_file_yields_what_it_can_without_throwing()
    {
        var file = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[] { SampleFrame("ok") });
        var chopped = file[..(file.Length - 6)];

        var packets = PcapngReader.Read(chopped);   // last block is incomplete

        Assert.NotNull(packets);   // must not throw; the complete blocks before it are still returned
    }

    [Fact]
    public void An_empty_file_yields_no_packets()
    {
        Assert.Empty(PcapngReader.Read(Array.Empty<byte>()));
    }

    private static string Payload(CapturedPacket p) =>
        Encoding.ASCII.GetString(PacketParser.Parse(p.LinkType, p.Data)!.Payload);

    // --- Regression: integer-overflow crashes on malformed input (adversarial review) ---

    private static byte[] OneBlock(uint blockType, uint totalLengthField, byte[] body)
    {
        // Builds a single block whose declared total_length can be a hostile value independent
        // of the real body size, to exercise the bounds checks.
        var block = new byte[12 + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(0), blockType);
        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(4), totalLengthField);
        body.CopyTo(block, 8);
        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(block.Length - 4), totalLengthField);
        return block;
    }

    [Fact]
    public void A_block_length_with_the_high_bit_set_does_not_over_read()
    {
        // total_length = 0x80000000 casts to a negative int on the old code, slipping past the
        // file-bounds check and over-reading a 40-byte buffer.
        var body = new byte[28];
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(12), 0x00100000);   // EPB captured len
        var file = OneBlock(0x00000006, 0x80000000, body);

        var packets = PcapngReader.Read(file);   // must not throw

        Assert.Empty(packets);
    }

    [Fact]
    public void A_block_length_that_would_move_the_cursor_backwards_is_rejected()
    {
        var file = OneBlock(0x00000006, 0xFFFFFFFC, new byte[20]);   // (int)0xFFFFFFFC = -4

        var packets = PcapngReader.Read(file);   // must not loop or throw

        Assert.Empty(packets);
    }

    [Fact]
    public void An_enhanced_packet_with_an_overflowing_captured_length_does_not_over_read()
    {
        // A well-framed 32-byte EPB whose captured-length field is int.MaxValue: dataStart +
        // captured overflows int on the old code and slips past the guard.
        var body = new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(12), 0x7FFFFFFF);   // captured
        var file = BuildValidHeaderThen(OneBlock(0x00000006, 32, body));

        var packets = PcapngReader.Read(file);   // must not throw

        Assert.Empty(packets);   // the bogus EPB yields nothing
    }

    [Fact]
    public void A_short_interface_block_keeps_later_link_types_aligned()
    {
        // Two interfaces: the first IDB is too short to hold a link type, the second is raw IP.
        // A packet on interface 1 must still resolve to raw IP, not shift onto interface 0.
        var shortIdb = OneBlock(0x00000001, 12, Array.Empty<byte>());
        var rawIdb = InterfaceBlock(PacketParser.LinkTypeRawIp);
        var pkt = EnhancedPacketOnInterface(1,
            PacketBuilders.Ipv4Tcp("10.0.0.1", 5, "10.0.0.2", 80, 1, Encoding.ASCII.GetBytes("x")));

        var file = Concat(Shb(), shortIdb, rawIdb, pkt);

        var p = Assert.Single(PcapngReader.Read(file));
        Assert.Equal(PacketParser.LinkTypeRawIp, p.LinkType);
    }

    // ---- helpers for the malformed/aligned cases ----

    private static byte[] Shb()
    {
        var body = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(0), 0x1A2B3C4D);
        for (var i = 8; i < 16; i++) { body[i] = 0xFF; }
        return OneBlock(0x0A0D0D0A, (uint)(12 + body.Length), body);
    }

    private static byte[] InterfaceBlock(int linkType)
    {
        var body = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(0), (ushort)linkType);
        return OneBlock(0x00000001, (uint)(12 + body.Length), body);
    }

    private static byte[] EnhancedPacketOnInterface(int interfaceId, byte[] data)
    {
        var padded = (data.Length + 3) & ~3;
        var body = new byte[20 + padded];
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(0), (uint)interfaceId);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(12), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(16), (uint)data.Length);
        data.CopyTo(body, 20);
        return OneBlock(0x00000006, (uint)(12 + body.Length), body);
    }

    private static byte[] BuildValidHeaderThen(byte[] block) =>
        Concat(Shb(), InterfaceBlock(PacketParser.LinkTypeEthernet), block);

    private static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var result = new byte[total];
        var o = 0;
        foreach (var p in parts) { p.CopyTo(result, o); o += p.Length; }
        return result;
    }

}

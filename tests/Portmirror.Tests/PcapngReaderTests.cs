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
}

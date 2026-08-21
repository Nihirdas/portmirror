using System.Text;
using Portmirror.Agent.Pcap;
using Xunit;

namespace Portmirror.Tests;

public class PacketParserTests
{
    private static byte[] Body(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void Parses_ethernet_ipv4_tcp_with_payload()
    {
        var ip = PacketBuilders.Ipv4Tcp("10.0.0.1", 51000, "10.0.0.2", 80, 1000, Body("GET / HTTP/1.1"), ack: true);
        var frame = PacketBuilders.Ethernet(0x0800, ip);

        var seg = PacketParser.Parse(PacketParser.LinkTypeEthernet, frame);

        Assert.NotNull(seg);
        Assert.Equal("10.0.0.1", seg!.Source.Address.ToString());
        Assert.Equal(51000, seg.Source.Port);
        Assert.Equal("10.0.0.2", seg.Destination.Address.ToString());
        Assert.Equal(80, seg.Destination.Port);
        Assert.Equal(1000u, seg.Sequence);
        Assert.True(seg.Ack);
        Assert.False(seg.Syn);
        Assert.Equal("GET / HTTP/1.1", Encoding.ASCII.GetString(seg.Payload));
    }

    [Fact]
    public void Parses_ipv6_tcp()
    {
        var ip = PacketBuilders.Ipv6Tcp("2001:db8::1", 4000, "2001:db8::2", 443, 5, Body("hi"));
        var frame = PacketBuilders.Ethernet(0x86DD, ip);

        var seg = PacketParser.Parse(PacketParser.LinkTypeEthernet, frame);

        Assert.NotNull(seg);
        Assert.Equal(443, seg!.Destination.Port);
        Assert.Equal("hi", Encoding.ASCII.GetString(seg.Payload));
    }

    [Fact]
    public void Sees_through_a_vlan_tag()
    {
        var ip = PacketBuilders.Ipv4Tcp("10.0.0.1", 9, "10.0.0.2", 80, 1, Body("x"));
        var frame = PacketBuilders.Ethernet(0x0800, ip, vlan: true);

        var seg = PacketParser.Parse(PacketParser.LinkTypeEthernet, frame);

        Assert.NotNull(seg);
        Assert.Equal("x", Encoding.ASCII.GetString(seg!.Payload));
    }

    [Fact]
    public void Parses_raw_ip_link_type_without_an_ethernet_header()
    {
        var ip = PacketBuilders.Ipv4Tcp("10.0.0.1", 1, "10.0.0.2", 80, 1, Body("raw"));

        var seg = PacketParser.Parse(PacketParser.LinkTypeRawIp, ip);

        Assert.NotNull(seg);
        Assert.Equal("raw", Encoding.ASCII.GetString(seg!.Payload));
    }

    [Fact]
    public void Decodes_syn_and_fin_flags()
    {
        var ip = PacketBuilders.Ipv4Tcp("10.0.0.1", 1, "10.0.0.2", 80, 1, Array.Empty<byte>(), syn: true);
        var syn = PacketParser.Parse(PacketParser.LinkTypeEthernet, PacketBuilders.Ethernet(0x0800, ip));
        Assert.True(syn!.Syn);
        Assert.False(syn.Ack);

        var ip2 = PacketBuilders.Ipv4Tcp("10.0.0.1", 1, "10.0.0.2", 80, 1, Array.Empty<byte>(), fin: true, ack: true);
        var fin = PacketParser.Parse(PacketParser.LinkTypeEthernet, PacketBuilders.Ethernet(0x0800, ip2));
        Assert.True(fin!.Fin);
        Assert.True(fin.Ack);
    }

    [Fact]
    public void Excludes_trailing_ethernet_padding_from_the_payload()
    {
        // IP total-length says 3 payload bytes; 20 extra pad bytes follow (min-frame padding).
        var ip = PacketBuilders.Ipv4Tcp("10.0.0.1", 1, "10.0.0.2", 80, 1, Body("abc"), trailingPad: 20);
        var seg = PacketParser.Parse(PacketParser.LinkTypeEthernet, PacketBuilders.Ethernet(0x0800, ip));

        Assert.Equal("abc", Encoding.ASCII.GetString(seg!.Payload));
    }

    [Fact]
    public void Returns_null_for_udp()
    {
        var frame = PacketBuilders.Ethernet(0x0800, PacketBuilders.Ipv4Udp("10.0.0.1", "10.0.0.2"));
        Assert.Null(PacketParser.Parse(PacketParser.LinkTypeEthernet, frame));
    }

    [Fact]
    public void Returns_null_for_a_non_ip_ethertype()
    {
        var arp = PacketBuilders.Ethernet(0x0806, new byte[28]);   // ARP
        Assert.Null(PacketParser.Parse(PacketParser.LinkTypeEthernet, arp));
    }

    [Fact]
    public void Returns_null_for_a_truncated_frame()
    {
        Assert.Null(PacketParser.Parse(PacketParser.LinkTypeEthernet, new byte[8]));
        Assert.Null(PacketParser.Parse(PacketParser.LinkTypeRawIp, new byte[5]));
    }
}

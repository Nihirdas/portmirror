using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// RemoteAddr arrives as a raw SOCKADDR. Observed live as "System.Byte[]" before decoding,
/// which is why the client address was missing from captured exchanges.
/// </summary>
public class SockAddrTests
{
    [Fact]
    public void Decodes_an_ipv4_sockaddr()
    {
        // AF_INET (2), port 4040, 10.0.0.5
        var raw = new byte[] { 0x02, 0x00, 0x0F, 0xC8, 10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0 };

        Assert.Equal("10.0.0.5", EtwCaptureService.ParseSockAddr(raw));
    }

    [Fact]
    public void Decodes_an_ipv6_sockaddr()
    {
        var raw = new byte[28];
        raw[0] = 23;                 // AF_INET6
        raw[8] = 0x20; raw[9] = 0x01; // 2001::1
        raw[23] = 0x01;

        Assert.Equal("2001::1", EtwCaptureService.ParseSockAddr(raw));
    }

    [Theory]
    [InlineData(null)]
    public void Handles_a_missing_payload(byte[]? raw)
    {
        Assert.Null(EtwCaptureService.ParseSockAddr(raw));
    }

    [Fact]
    public void Ignores_a_truncated_buffer()
    {
        Assert.Null(EtwCaptureService.ParseSockAddr(new byte[] { 0x02, 0x00, 0x0F }));
    }

    [Fact]
    public void Ignores_an_unknown_address_family()
    {
        var raw = new byte[16];
        raw[0] = 99;

        Assert.Null(EtwCaptureService.ParseSockAddr(raw));
    }

    [Fact]
    public void Ignores_a_truncated_ipv6_buffer()
    {
        var raw = new byte[12];
        raw[0] = 23;

        Assert.Null(EtwCaptureService.ParseSockAddr(raw));
    }
}

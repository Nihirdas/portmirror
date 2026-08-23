using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// F5 and other TCP health monitors open a socket without sending an HTTP request, so HTTP.SYS
/// completes an exchange with a client address but no request line. Left in, at health-check
/// volume those blank rows fill the ring and evict the body-bearing captures that matter.
/// </summary>
public class EtwNoiseSuppressionTests
{
    [Fact]
    public void ConnectionOnlyRow_WithClientButNoRequestLine_IsContentless()
    {
        var noise = new Exchange { ClientIp = "10.8.236.2" };
        Assert.True(EtwCaptureService.IsContentless(noise));
    }

    [Theory]
    [InlineData("GET", "https://host/", null)]   // real inbound request
    [InlineData(null, "https://host/", null)]    // url alone is content
    [InlineData(null, null, 500)]                // a status alone is content
    [InlineData("POST", null, null)]             // a verb alone is content
    public void RowWithAnyRequestOrResponseLine_IsKept(string? verb, string? url, int? status)
    {
        var e = new Exchange { Verb = verb, Url = url, StatusCode = status, ClientIp = "10.8.236.2" };
        Assert.False(EtwCaptureService.IsContentless(e));
    }
}

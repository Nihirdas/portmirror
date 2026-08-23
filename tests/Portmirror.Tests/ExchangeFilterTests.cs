using Portmirror.Agent.Api;
using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// The listing/stream/export share one filter. Direction and bodies were added so a server-to-server
/// call can be found among a flood of inbound rows.
/// </summary>
public class ExchangeFilterTests
{
    private static Exchange Outbound() => new()
    {
        Verb = "POST", Url = "/coordinator",
        Direction = CaptureDirection.Outbound, Tier = CaptureTier.PacketCapture,
        Request = new HttpMessage { Body = "<xml/>", BodyFormat = "xml", BodyByteCount = 6 }
    };

    private static Exchange InboundMetadata() => new()
    {
        Verb = "GET", Url = "https://host/",
        Direction = CaptureDirection.Inbound, Tier = CaptureTier.EtwMetadata
    };

    [Fact]
    public void NoCriteria_ReturnsNullFilter()
    {
        Assert.Null(ApiEndpoints.BuildFilter(null, null, null, null));
    }

    [Fact]
    public void Direction_KeepsOnlyThatDirection()
    {
        var f = ApiEndpoints.BuildFilter(null, null, "Outbound", null);
        Assert.NotNull(f);
        Assert.True(f!(Outbound()));
        Assert.False(f(InboundMetadata()));
    }

    [Fact]
    public void DirectionParse_IsCaseInsensitive()
    {
        var f = ApiEndpoints.BuildFilter(null, null, "outbound", null);
        Assert.NotNull(f);
        Assert.True(f!(Outbound()));
    }

    [Fact]
    public void Bodies_KeepsOnlyExchangesThatCarryABody()
    {
        var f = ApiEndpoints.BuildFilter(null, null, null, true);
        Assert.NotNull(f);
        Assert.True(f!(Outbound()));          // has a request body
        Assert.False(f(InboundMetadata()));   // metadata only
    }

    [Fact]
    public void UnknownDirectionString_DoesNotBecomeAFilter()
    {
        Assert.Null(ApiEndpoints.BuildFilter(null, null, "sideways", null));
    }
}

using Portmirror.Agent.Pcap;
using Xunit;

namespace Portmirror.Tests;

public class PcapFeedServiceTests
{
    [Fact]
    public void A_named_server_port_filters_on_the_port_alone()
    {
        // Combining `-t TCP` with `-p <port>` in one pktmon filter captures almost nothing on
        // Server 2022 (measured); the port on its own captures the whole conversation. Guard
        // against the transport type creeping back in.
        var args = PcapFeedService.BuildFilterArgs(new[] { 8080 });

        Assert.Equal("filter add portmirror -p 8080", args);
        Assert.DoesNotContain("-t TCP", args);
    }

    [Fact]
    public void The_first_named_port_is_used()
    {
        Assert.Equal("filter add portmirror -p 9000", PcapFeedService.BuildFilterArgs(new[] { 9000, 9001 }));
    }

    [Fact]
    public void With_no_named_port_it_captures_all_tcp()
    {
        Assert.Equal("filter add portmirror -t TCP", PcapFeedService.BuildFilterArgs(null));
        Assert.Equal("filter add portmirror -t TCP", PcapFeedService.BuildFilterArgs(System.Array.Empty<int>()));
    }
}

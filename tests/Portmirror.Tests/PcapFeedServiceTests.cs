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
        var cmds = PcapFeedService.BuildFilterCommands(new[] { 8080 });

        Assert.Equal(new[] { "filter add portmirror8080 -p 8080" }, cmds);
        Assert.DoesNotContain("-t TCP", cmds[0]);
    }

    [Fact]
    public void Every_named_port_gets_its_own_filter()
    {
        // pktmon takes one port per filter and ORs them, so scoping to several downstreams
        // (e.g. coordinator and STS) needs one filter each — the first-port-only behaviour
        // silently dropped every other downstream.
        var cmds = PcapFeedService.BuildFilterCommands(new[] { 5202, 1010 });

        Assert.Equal(new[] { "filter add portmirror5202 -p 5202", "filter add portmirror1010 -p 1010" }, cmds);
    }

    [Fact]
    public void Duplicate_and_invalid_ports_are_dropped()
    {
        var cmds = PcapFeedService.BuildFilterCommands(new[] { 5202, 5202, 0, -1 });

        Assert.Equal(new[] { "filter add portmirror5202 -p 5202" }, cmds);
    }

    [Fact]
    public void With_no_named_port_it_captures_all_tcp()
    {
        Assert.Equal(new[] { "filter add portmirror -t TCP" }, PcapFeedService.BuildFilterCommands(null));
        Assert.Equal(new[] { "filter add portmirror -t TCP" }, PcapFeedService.BuildFilterCommands(System.Array.Empty<int>()));
    }
}

using System.Collections.Generic;
using Portmirror.Agent.Http;
using Portmirror.Agent.Pcap;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// An origin-form request line has only the path; the host is in the Host header. An outbound row
/// should show which downstream it hit, so the two are reunited into a full URL.
/// </summary>
public class FullUrlTests
{
    private static ParsedMessage Req(string target, string? host)
    {
        var headers = new List<KeyValuePair<string, string>>();
        if (host is not null) { headers.Add(new KeyValuePair<string, string>("Host", host)); }
        return new ParsedMessage { Method = "POST", Target = target, Headers = headers };
    }

    [Fact]
    public void Combines_host_and_path()
    {
        Assert.Equal("http://se-mws-0038:5202/coordinator",
            TcpFlowReassembler.FullUrl(Req("/coordinator", "se-mws-0038:5202")));
    }

    [Fact]
    public void No_host_returns_the_path_alone()
    {
        Assert.Equal("/coordinator", TcpFlowReassembler.FullUrl(Req("/coordinator", null)));
    }

    [Fact]
    public void Absolute_target_is_left_as_is()
    {
        Assert.Equal("http://x/y", TcpFlowReassembler.FullUrl(Req("http://x/y", "ignored")));
    }

    [Fact]
    public void Null_or_empty_target_is_null()
    {
        Assert.Null(TcpFlowReassembler.FullUrl(null));
        Assert.Null(TcpFlowReassembler.FullUrl(Req("", "h")));
    }
}

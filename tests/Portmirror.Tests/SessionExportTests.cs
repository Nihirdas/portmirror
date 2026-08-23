using System.Collections.Generic;
using Portmirror.Agent.Api;
using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

/// <summary>The raw export is a flat transcript meant to read cleanly and feed into other tools.</summary>
public class SessionExportTests
{
    [Fact]
    public void RawDump_IncludesDirectionTierHeadersAndBothBodies()
    {
        var e = new Exchange
        {
            Seq = 42, Verb = "POST", Url = "/coordinator",
            Direction = CaptureDirection.Outbound, Tier = CaptureTier.PacketCapture,
            Request = new HttpMessage
            {
                Headers = { ["SOAPAction"] = "\"IssueRenderedCheque\"", ["Host"] = "se-mws-0038:5202" },
                Body = "<Envelope/>", BodyFormat = "xml", BodyByteCount = 11
            },
            Response = new HttpMessage
            {
                Headers = { ["Content-Type"] = "text/xml" },
                Body = "<Fault/>", BodyFormat = "xml", BodyByteCount = 8
            }
        };

        var dump = ApiEndpoints.RawDump(new List<Exchange> { e });

        Assert.Contains("[PacketCapture/Outbound]", dump);
        Assert.Contains("POST /coordinator", dump);
        Assert.Contains("SOAPAction: \"IssueRenderedCheque\"", dump);
        Assert.Contains("REQUEST", dump);
        Assert.Contains("<Envelope/>", dump);
        Assert.Contains("RESPONSE", dump);
        Assert.Contains("<Fault/>", dump);
    }

    [Fact]
    public void RawDump_MarksPartial_AndOmitsAnAbsentResponse()
    {
        var e = new Exchange
        {
            Seq = 7, Verb = "POST", Url = "/coordinator",
            Direction = CaptureDirection.Outbound, Tier = CaptureTier.PacketCapture, Partial = true,
            Request = new HttpMessage { Body = "<x/>", BodyFormat = "xml", BodyByteCount = 4 }
        };

        var dump = ApiEndpoints.RawDump(new List<Exchange> { e });

        Assert.Contains("(partial)", dump);
        Assert.Contains("REQUEST", dump);
        Assert.DoesNotContain("RESPONSE", dump);
    }
}

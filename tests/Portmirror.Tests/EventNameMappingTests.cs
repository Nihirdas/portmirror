using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// The event names below were read off a live Windows Server 2022 box (build 20348) from the
/// agent's own /api/diagnostics/etw endpoint, so they are observations rather than guesses.
///
/// The important one: that build emits no EndRequest event at all. SendComplete is what
/// terminates a request, and mapping only EndRequest as terminal means nothing ever completes.
/// </summary>
public class EventNameMappingTests
{
    [Theory]
    // Observed on Server 2022, build 20348.
    [InlineData("HTTPRequestTraceTask/RecvReq", SignalKind.RequestReceived)]
    [InlineData("HTTPRequestTraceTask/Parse", SignalKind.RequestParsed)]
    [InlineData("HTTPRequestTraceTask/Deliver", SignalKind.Delivered)]
    [InlineData("HTTPRequestTraceTask/FastResp", SignalKind.ResponseSent)]
    [InlineData("HTTPRequestTraceTask/FastRespLast", SignalKind.ResponseSent)]
    [InlineData("HTTPRequestTraceTask/FastSend", SignalKind.ResponseSent)]
    [InlineData("HTTPRequestTraceTask/RecvRespLast", SignalKind.ResponseSent)]
    [InlineData("HTTPRequestTraceTask/SendComplete", SignalKind.RequestEnded)]
    [InlineData("HTTPRequestTraceTask/RequestRejected", SignalKind.RequestEnded)]
    // Connection-scoped events carry no request identity and must not be treated as lifecycle.
    [InlineData("HTTPConnectionTraceTask/ConnConnect", SignalKind.Other)]
    [InlineData("HTTPConnectionTraceTask/ConnIdAssgn", SignalKind.Other)]
    [InlineData("HTTPConnectionTraceTask/ConnClose", SignalKind.Other)]
    [InlineData("HTTPConnectionTraceTask/ConnCleanup", SignalKind.Other)]
    // Names from builds that render without the task separator, kept working on purpose.
    [InlineData("HTTPRequestTraceTaskRecvReq", SignalKind.RequestReceived)]
    [InlineData("HTTPRequestTraceTaskSendResponse", SignalKind.ResponseSent)]
    [InlineData("HTTPRequestTraceTaskSrvdFrmCache", SignalKind.CacheServed)]
    [InlineData("HTTPRequestTraceTaskEndRequest", SignalKind.RequestEnded)]
    [InlineData("SomethingElseEntirely", SignalKind.Other)]
    [InlineData("", SignalKind.Other)]
    [InlineData(null, SignalKind.Other)]
    public void Maps_http_sys_event_names(string? eventName, SignalKind expected)
    {
        Assert.Equal(expected, EtwCaptureService.MapKind(eventName));
    }

    [Fact]
    public void SendComplete_is_terminal_because_Server_2022_emits_no_EndRequest()
    {
        Assert.Equal(SignalKind.RequestEnded, EtwCaptureService.MapKind("HTTPRequestTraceTask/SendComplete"));
    }

    [Fact]
    public void A_rejected_request_terminates_rather_than_hanging_until_the_idle_sweep()
    {
        Assert.Equal(SignalKind.RequestEnded, EtwCaptureService.MapKind("HTTPRequestTraceTask/RequestRejected"));
    }

    [Fact]
    public void RecvRespLast_is_a_response_marker_not_a_received_request()
    {
        Assert.Equal(SignalKind.ResponseSent, EtwCaptureService.MapKind("HTTPRequestTraceTask/RecvRespLast"));
    }
}

/// <summary>
/// HTTP.SYS reports the verb as an enum ordinal on Parse and as text elsewhere. Observed
/// live: Parse carried HttpVerb = "4", which is GET.
/// </summary>
public class VerbNormalisationTests
{
    [Theory]
    [InlineData("4", "GET")]
    [InlineData("6", "POST")]
    [InlineData("7", "PUT")]
    [InlineData("8", "DELETE")]
    [InlineData("3", "OPTIONS")]
    [InlineData("5", "HEAD")]
    public void Maps_enum_ordinals_to_verbs(string raw, string expected)
    {
        Assert.Equal(expected, EtwCaptureService.NormalizeVerb(raw));
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public void Passes_through_text_verbs(string raw)
    {
        Assert.Equal(raw, EtwCaptureService.NormalizeVerb(raw));
    }

    [Theory]
    [InlineData("0")]   // Unparsed
    [InlineData("1")]   // Unknown
    [InlineData("2")]   // Invalid
    [InlineData("999")]
    public void Reports_nothing_rather_than_a_meaningless_ordinal(string raw)
    {
        Assert.Null(EtwCaptureService.NormalizeVerb(raw));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Handles_absent_values(string? raw)
    {
        Assert.Null(EtwCaptureService.NormalizeVerb(raw));
    }
}

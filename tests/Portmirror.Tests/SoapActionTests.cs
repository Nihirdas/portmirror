using Portmirror.Agent.Api;
using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// SOAP calls all POST to the same endpoint, so the SOAPAction header is what tells them apart in
/// a listing. It is surfaced per row, cleaned of quotes and reduced to its final segment.
/// </summary>
public class SoapActionTests
{
    private static HttpMessage WithHeader(string name, string value)
    {
        var m = new HttpMessage();
        m.Headers[name] = value;
        return m;
    }

    [Fact]
    public void A_bare_action_is_returned_unquoted()
    {
        Assert.Equal("SearchNew", ApiEndpoints.SoapAction(WithHeader("SOAPAction", "\"SearchNew\"")));
    }

    [Fact]
    public void A_namespaced_action_is_reduced_to_its_final_segment()
    {
        Assert.Equal("Search",
            ApiEndpoints.SoapAction(WithHeader("SOAPAction", "\"http://example.com/Service/Search\"")));
        Assert.Equal("RefreshSessionToken",
            ApiEndpoints.SoapAction(WithHeader("SOAPAction", "\"http://tempuri.org/ISvc/RefreshSessionToken\"")));
    }

    [Fact]
    public void A_fragment_style_action_is_reduced_to_its_final_segment()
    {
        Assert.Equal("DoThing", ApiEndpoints.SoapAction(WithHeader("SOAPAction", "\"urn:Service#DoThing\"")));
    }

    [Fact]
    public void The_header_is_matched_case_insensitively()
    {
        Assert.Equal("Ping", ApiEndpoints.SoapAction(WithHeader("soapaction", "\"Ping\"")));
    }

    [Fact]
    public void No_soap_action_yields_null()
    {
        Assert.Null(ApiEndpoints.SoapAction(null));
        Assert.Null(ApiEndpoints.SoapAction(new HttpMessage()));
        Assert.Null(ApiEndpoints.SoapAction(WithHeader("SOAPAction", "\"\"")));
        Assert.Null(ApiEndpoints.SoapAction(WithHeader("Content-Type", "text/xml")));
    }
}

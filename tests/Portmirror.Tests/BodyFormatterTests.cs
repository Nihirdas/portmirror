using Portmirror.Agent.Http;
using Xunit;

namespace Portmirror.Tests;

public class BodyFormatterTests
{
    [Theory]
    [InlineData("application/json", "{\"a\":1}", BodyFormat.Json)]
    [InlineData("text/plain", "{\"a\":1}", BodyFormat.Json)]        // mislabelled JSON
    [InlineData("application/json", "[1,2,3]", BodyFormat.Json)]
    [InlineData("application/xml", "<r/>", BodyFormat.Xml)]
    [InlineData("text/plain", "<r><a/></r>", BodyFormat.Xml)]        // mislabelled XML
    [InlineData("text/html", "<html></html>", BodyFormat.Text)]      // HTML is not XML
    [InlineData("text/plain", "just words", BodyFormat.Text)]
    [InlineData("application/json", "", BodyFormat.Empty)]
    [InlineData(null, "   ", BodyFormat.Text)]
    public void Detect_classifies_by_shape_then_content_type(string? ct, string body, BodyFormat expected)
    {
        Assert.Equal(expected, BodyFormatter.Detect(ct, body));
    }

    [Fact]
    public void Detect_treats_null_body_as_empty()
    {
        Assert.Equal(BodyFormat.Empty, BodyFormatter.Detect("application/json", null));
    }

    [Fact]
    public void Pretty_indents_json_and_preserves_key_order()
    {
        var pretty = BodyFormatter.Pretty("{\"b\":2,\"a\":1}", "application/json");

        Assert.Contains("\n", pretty);
        Assert.True(pretty.IndexOf("\"b\"", System.StringComparison.Ordinal)
                    < pretty.IndexOf("\"a\"", System.StringComparison.Ordinal),
            "JSON key order must be preserved");
    }

    [Fact]
    public void Pretty_keeps_readable_angle_brackets_in_json_strings()
    {
        var pretty = BodyFormatter.Pretty("{\"html\":\"<b>hi</b>\"}", "application/json");

        // Relaxed escaping: not turned into < etc.
        Assert.Contains("<b>hi</b>", pretty);
    }

    [Fact]
    public void Pretty_indents_xml()
    {
        var pretty = BodyFormatter.Pretty("<order><id>8841</id></order>", "application/xml");

        Assert.Contains("\n", pretty);
        Assert.Contains("<id>8841</id>", pretty);
    }

    [Fact]
    public void Pretty_returns_malformed_json_unchanged()
    {
        const string broken = "{\"a\":";
        Assert.Equal(broken, BodyFormatter.Pretty(broken, "application/json"));
    }

    [Fact]
    public void Pretty_returns_malformed_xml_unchanged()
    {
        const string broken = "<open>no close";
        Assert.Equal(broken, BodyFormatter.Pretty(broken, "application/xml"));
    }

    [Fact]
    public void Pretty_leaves_plain_text_alone()
    {
        const string text = "hello world";
        Assert.Equal(text, BodyFormatter.Pretty(text, "text/plain"));
    }

    [Fact]
    public void Pretty_does_not_resolve_external_entities()
    {
        // An XXE attempt: with external resolution disabled the parse fails and the body is
        // returned verbatim — never the contents of the referenced resource.
        const string xxe =
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><foo>&x;</foo>";

        var result = BodyFormatter.Pretty(xxe, "application/xml");

        Assert.Equal(xxe, result);
        Assert.DoesNotContain("root:", result);
    }
}

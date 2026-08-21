using Portmirror.Agent.Redaction;
using Xunit;

namespace Portmirror.Tests;

public class RedactorTests
{
    private readonly Redactor _redactor = new(enabled: true);

    [Fact]
    public void Masks_a_card_number_keeping_the_last_four()
    {
        var result = _redactor.RedactBody("{\"pan\":\"4111111111111111\"}");

        Assert.Equal("{\"pan\":\"************1111\"}", result);
    }

    [Fact]
    public void Leaves_long_numbers_that_are_not_cards_alone()
    {
        // 13 ones fails the Luhn check, so it is an identifier rather than a PAN.
        const string body = "{\"orderId\":\"1111111111111\"}";

        Assert.Equal(body, _redactor.RedactBody(body));
    }

    [Fact]
    public void Masks_json_credentials()
    {
        var result = _redactor.RedactBody("{\"user\":\"nk\",\"password\":\"hunter2\"}");

        Assert.Contains(Redactor.Mask, result!);
        Assert.DoesNotContain("hunter2", result!);
        Assert.Contains("\"user\":\"nk\"", result!);
    }

    [Fact]
    public void Masks_xml_card_verification_values()
    {
        var result = _redactor.RedactBody("<Payment><Cvv>123</Cvv><Amount>10</Amount></Payment>");

        Assert.Equal($"<Payment><Cvv>{Redactor.Mask}</Cvv><Amount>10</Amount></Payment>", result);
    }

    [Fact]
    public void Masks_sensitive_headers_and_keeps_the_rest()
    {
        var headers = new Dictionary<string, string>
        {
            ["Authorization"] = "Bearer abc.def.ghi",
            ["Cookie"] = "session=1",
            ["Content-Type"] = "application/json"
        };

        var result = _redactor.RedactHeaders(headers);

        Assert.Equal(Redactor.Mask, result["Authorization"]);
        Assert.Equal(Redactor.Mask, result["Cookie"]);
        Assert.Equal("application/json", result["Content-Type"]);
    }

    [Fact]
    public void Header_lookup_ignores_case()
    {
        var result = _redactor.RedactHeaders(
            new Dictionary<string, string> { ["AUTHORIZATION"] = "Bearer x" });

        Assert.Equal(Redactor.Mask, result["authorization"]);
    }

    [Fact]
    public void Masks_cards_in_a_query_string()
    {
        var result = _redactor.RedactUrl("/pay?pan=4111111111111111&amt=10");

        Assert.Equal("/pay?pan=************1111&amt=10", result);
    }

    [Fact]
    public void Disabled_redactor_is_a_passthrough()
    {
        var off = new Redactor(enabled: false);
        const string body = "{\"password\":\"hunter2\",\"pan\":\"4111111111111111\"}";

        Assert.Equal(body, off.RedactBody(body));
        Assert.Equal("Bearer x", off.RedactHeaders(
            new Dictionary<string, string> { ["Authorization"] = "Bearer x" })["Authorization"]);
    }

    [Fact]
    public void Handles_null_and_empty_input()
    {
        Assert.Null(_redactor.RedactBody(null));
        Assert.Equal(string.Empty, _redactor.RedactBody(string.Empty));
        Assert.Null(_redactor.RedactUrl(null));
    }

    [Theory]
    [InlineData("4111111111111111", true)]
    [InlineData("5500000000000004", true)]
    [InlineData("1111111111111", false)]
    [InlineData("4111111111111112", false)]
    public void Luhn_check_behaves(string digits, bool expected)
    {
        Assert.Equal(expected, Redactor.PassesLuhn(digits));
    }
}

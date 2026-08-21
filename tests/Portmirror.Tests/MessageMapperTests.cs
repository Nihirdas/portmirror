using System.Text;
using Portmirror.Agent.Http;
using Portmirror.Agent.Redaction;
using Xunit;

namespace Portmirror.Tests;

public class MessageMapperTests
{
    private static ParsedMessage Msg(
        string contentType, string body, MessageKind kind = MessageKind.Request,
        params (string, string)[] headers)
    {
        var m = new ParsedMessage
        {
            Kind = kind,
            Method = kind == MessageKind.Request ? "POST" : null,
            Target = kind == MessageKind.Request ? "/api/x" : null,
            StatusCode = kind == MessageKind.Response ? 200 : null,
            Body = Encoding.UTF8.GetBytes(body)
        };
        m.Headers.Add(new("Content-Type", contentType));
        foreach (var (k, v) in headers)
        {
            m.Headers.Add(new(k, v));
        }
        return m;
    }

    [Fact]
    public void Maps_a_json_body_and_reports_its_format()
    {
        var mapped = MessageMapper.ToHttpMessage(Msg("application/json", "{\"ok\":true}"), new Redactor(true));

        Assert.Equal("json", mapped.BodyFormat);
        Assert.Equal("{\"ok\":true}", mapped.Body);
        Assert.Equal("application/json", mapped.ContentType);
        Assert.False(mapped.BodyRedacted);
    }

    [Fact]
    public void Redacts_a_secret_in_the_body_and_flags_it()
    {
        var mapped = MessageMapper.ToHttpMessage(
            Msg("application/json", "{\"password\":\"hunter2\"}"), new Redactor(true));

        Assert.DoesNotContain("hunter2", mapped.Body);
        Assert.Contains(Redactor.Mask, mapped.Body!);
        Assert.True(mapped.BodyRedacted);
    }

    [Fact]
    public void Redacts_sensitive_headers()
    {
        var mapped = MessageMapper.ToHttpMessage(
            Msg("application/json", "{}", MessageKind.Request, ("Authorization", "Bearer abc.def")),
            new Redactor(true));

        Assert.Equal(Redactor.Mask, mapped.Headers["Authorization"]);
        Assert.Equal("application/json", mapped.Headers["Content-Type"]);
    }

    [Fact]
    public void A_disabled_redactor_leaves_the_body_untouched()
    {
        var mapped = MessageMapper.ToHttpMessage(
            Msg("application/json", "{\"password\":\"hunter2\"}"), new Redactor(false));

        Assert.Contains("hunter2", mapped.Body);
        Assert.False(mapped.BodyRedacted);
    }

    [Fact]
    public void A_binary_body_keeps_its_size_but_drops_its_bytes()
    {
        var m = new ParsedMessage { Kind = MessageKind.Response, StatusCode = 200 };
        m.Headers.Add(new("Content-Type", "application/octet-stream"));
        m.Body = new byte[] { 0x00, 0x01, 0x02, 0xFF, 0xFE };

        var mapped = MessageMapper.ToHttpMessage(m, new Redactor(true));

        Assert.Equal("binary", mapped.BodyFormat);
        Assert.Null(mapped.Body);
        Assert.Equal(5, mapped.BodyByteCount);
    }

    [Fact]
    public void An_empty_body_is_reported_as_empty()
    {
        var m = new ParsedMessage { Kind = MessageKind.Response, StatusCode = 204 };
        var mapped = MessageMapper.ToHttpMessage(m, new Redactor(true));

        Assert.Equal("empty", mapped.BodyFormat);
        Assert.Null(mapped.Body);
        Assert.Equal(0, mapped.BodyByteCount);
    }

    [Fact]
    public void Carries_truncation_and_decode_flags_across()
    {
        var m = Msg("application/json", "{\"partial\":true");
        m.BodyTruncated = true;
        m.DecodeError = "could not decompress gzip";

        var mapped = MessageMapper.ToHttpMessage(m, new Redactor(true));

        Assert.True(mapped.BodyTruncated);
        Assert.Equal("could not decompress gzip", mapped.DecodeError);
    }

    [Fact]
    public void Masks_a_card_number_in_the_body()
    {
        var mapped = MessageMapper.ToHttpMessage(
            Msg("text/plain", "pan=4111111111111111"), new Redactor(true));

        Assert.DoesNotContain("4111111111111111", mapped.Body);
        Assert.True(mapped.BodyRedacted);
    }

    [Fact]
    public void Reports_content_length_from_the_parsed_message()
    {
        var m = Msg("application/json", "{}");
        var withLen = new ParsedMessage
        {
            Kind = m.Kind, Method = m.Method, Target = m.Target,
            ContentLength = 2, Body = m.Body
        };
        withLen.Headers.Add(new("Content-Type", "application/json"));

        var mapped = MessageMapper.ToHttpMessage(withLen, new Redactor(true));
        Assert.Equal(2, mapped.ContentLength);
    }
}

using System.IO.Compression;
using System.Text;
using Portmirror.Agent.Http;
using Xunit;

namespace Portmirror.Tests;

public class HttpMessageParserTests
{
    private static byte[] B(string s) => Encoding.ASCII.GetBytes(s.Replace("\n", "\r\n"));
    private static string Body(ParsedMessage m) => Encoding.UTF8.GetString(m.Body);

    [Fact]
    public void Parses_a_request_with_a_content_length_body()
    {
        var p = new HttpMessageParser(MessageKind.Request);
        var done = p.Append(B("POST /api/orders HTTP/1.1\nHost: srv\nContent-Length: 12\n\n{\"total\":42}"));

        var m = Assert.Single(done);
        Assert.Equal("POST", m.Method);
        Assert.Equal("/api/orders", m.Target);
        Assert.Equal("HTTP/1.1", m.Version);
        Assert.Equal("srv", m.Header("host"));
        Assert.Equal("{\"total\":42}", Body(m));
        Assert.False(m.BodyTruncated);
    }

    [Fact]
    public void Parses_a_response_with_a_content_length_body()
    {
        var p = new HttpMessageParser(MessageKind.Response);
        var done = p.Append(B("HTTP/1.1 404 Not Found\nContent-Type: application/json\nContent-Length: 16\n\n{\"error\":\"gone\"}"));

        var m = Assert.Single(done);
        Assert.Equal(404, m.StatusCode);
        Assert.Equal("Not Found", m.ReasonPhrase);
        Assert.Equal("application/json", m.ContentType);
        Assert.Equal("{\"error\":\"gone\"}", Body(m));
    }

    [Fact]
    public void One_byte_at_a_time_gives_the_same_result_as_one_block()
    {
        var raw = B("POST /x HTTP/1.1\nContent-Length: 5\n\nhello");
        var p = new HttpMessageParser(MessageKind.Request);

        ParsedMessage? got = null;
        for (var i = 0; i < raw.Length; i++)
        {
            foreach (var m in p.Append(raw, i, 1))
            {
                got = m;
            }
        }

        Assert.NotNull(got);
        Assert.Equal("hello", Body(got!));
    }

    [Fact]
    public void Reassembles_a_chunked_body()
    {
        var p = new HttpMessageParser(MessageKind.Response);
        var done = p.Append(B(
            "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n" +
            "5\nhello\n" +
            "6\n world\n" +
            "0\n\n"));

        var m = Assert.Single(done);
        Assert.True(m.Chunked);
        Assert.Equal("hello world", Body(m));
    }

    [Fact]
    public void Ignores_chunk_extensions()
    {
        var p = new HttpMessageParser(MessageKind.Response);
        var done = p.Append(B("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n4;name=value\nabcd\n0\n\n"));

        Assert.Equal("abcd", Body(Assert.Single(done)));
    }

    [Fact]
    public void Keeps_chunked_trailers_as_headers()
    {
        var p = new HttpMessageParser(MessageKind.Response);
        var done = p.Append(B(
            "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n3\nabc\n0\nX-Checksum: 99\n\n"));

        var m = Assert.Single(done);
        Assert.Equal("abc", Body(m));
        Assert.Equal("99", m.Header("X-Checksum"));
    }

    [Fact]
    public void Splits_pipelined_requests_on_one_connection()
    {
        var p = new HttpMessageParser(MessageKind.Request);
        var done = p.Append(B(
            "GET /one HTTP/1.1\nContent-Length: 1\n\na" +
            "GET /two HTTP/1.1\nContent-Length: 1\n\nb"));

        Assert.Equal(2, done.Count);
        Assert.Equal("/one", done[0].Target);
        Assert.Equal("a", Body(done[0]));
        Assert.Equal("/two", done[1].Target);
        Assert.Equal("b", Body(done[1]));
    }

    [Theory]
    [InlineData(204)]
    [InlineData(304)]
    [InlineData(100)]
    public void Statuses_that_cannot_carry_a_body_complete_at_the_headers(int status)
    {
        var p = new HttpMessageParser(MessageKind.Response);
        var done = p.Append(B($"HTTP/1.1 {status} Whatever\nContent-Length: 99\n\n"));

        var m = Assert.Single(done);
        Assert.Equal(status, m.StatusCode);
        Assert.Empty(m.Body);
    }

    [Fact]
    public void A_head_response_has_no_body_even_though_it_advertises_a_length()
    {
        var p = new HttpMessageParser(MessageKind.Response) { NextResponseHasNoBody = true };
        var done = p.Append(B("HTTP/1.1 200 OK\nContent-Length: 500\n\n"));

        Assert.Empty(Assert.Single(done).Body);
    }

    [Fact]
    public void A_response_with_no_length_runs_until_the_connection_closes()
    {
        var p = new HttpMessageParser(MessageKind.Response);

        Assert.Empty(p.Append(B("HTTP/1.0 200 OK\nContent-Type: text/plain\n\nstreamed body")));

        var m = p.Finish();
        Assert.NotNull(m);
        Assert.Equal("streamed body", Body(m!));
    }

    [Fact]
    public void A_request_with_no_length_has_no_body()
    {
        var p = new HttpMessageParser(MessageKind.Request);
        var done = p.Append(B("GET /plain HTTP/1.1\nHost: srv\n\n"));

        var m = Assert.Single(done);
        Assert.Empty(m.Body);
        Assert.False(p.HasPartialMessage);
    }

    [Fact]
    public void An_interrupted_body_is_reported_as_truncated_rather_than_lost()
    {
        var p = new HttpMessageParser(MessageKind.Request);
        Assert.Empty(p.Append(B("POST /x HTTP/1.1\nContent-Length: 100\n\nonly-this-much")));

        var m = p.Finish();
        Assert.NotNull(m);
        Assert.True(m!.BodyTruncated);
        Assert.Equal("only-this-much", Body(m));
    }

    [Fact]
    public void A_body_over_the_cap_is_capped_and_flagged()
    {
        var p = new HttpMessageParser(MessageKind.Request, maxBodyBytes: 8);
        var done = p.Append(B("POST /x HTTP/1.1\nContent-Length: 20\n\nabcdefghijklmnopqrst"));

        var m = Assert.Single(done);
        Assert.True(m.BodyTruncated);
        Assert.Equal(8, m.Body.Length);
        Assert.Equal("abcdefgh", Body(m));
    }

    [Fact]
    public void Joins_a_folded_header_onto_the_line_before_it()
    {
        var p = new HttpMessageParser(MessageKind.Request);
        var done = p.Append(B("GET /x HTTP/1.1\nX-Long: first\n  second\nContent-Length: 0\n\n"));

        Assert.Equal("first second", Assert.Single(done).Header("X-Long"));
    }

    [Fact]
    public void Accepts_bare_line_feeds()
    {
        var p = new HttpMessageParser(MessageKind.Request);
        var done = p.Append(Encoding.ASCII.GetBytes("GET /x HTTP/1.1\nContent-Length: 2\n\nhi"));

        Assert.Equal("hi", Body(Assert.Single(done)));
    }

    [Fact]
    public void Header_lookup_ignores_case()
    {
        var p = new HttpMessageParser(MessageKind.Response);
        var m = Assert.Single(p.Append(B("HTTP/1.1 200 OK\nCoNtEnT-tYpE: text/xml\nContent-Length: 0\n\n")));

        Assert.Equal("text/xml", m.Header("content-type"));
        Assert.Equal("text/xml", m.ContentType);
    }

    [Fact]
    public void Decompresses_a_gzip_body()
    {
        var payload = Encoding.UTF8.GetBytes("{\"compressed\":true}");
        byte[] gz;
        using (var ms = new MemoryStream())
        {
            using (var g = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            {
                g.Write(payload, 0, payload.Length);
            }
            gz = ms.ToArray();
        }

        var head = B($"HTTP/1.1 200 OK\nContent-Encoding: gzip\nContent-Length: {gz.Length}\n\n");
        var all = new byte[head.Length + gz.Length];
        Buffer.BlockCopy(head, 0, all, 0, head.Length);
        Buffer.BlockCopy(gz, 0, all, head.Length, gz.Length);

        var m = Assert.Single(new HttpMessageParser(MessageKind.Response).Append(all));

        Assert.True(m.BodyDecompressed);
        Assert.Null(m.DecodeError);
        Assert.Equal("{\"compressed\":true}", Body(m));
    }

    [Fact]
    public void Reports_an_encoding_it_cannot_undo_instead_of_faking_success()
    {
        var p = new HttpMessageParser(MessageKind.Response);
        var m = Assert.Single(p.Append(B("HTTP/1.1 200 OK\nContent-Encoding: br\nContent-Length: 4\n\nzzzz")));

        Assert.False(m.BodyDecompressed);
        Assert.NotNull(m.DecodeError);
        Assert.Equal("zzzz", Body(m));
    }

    [Fact]
    public void Garbage_does_not_wedge_the_parser()
    {
        var p = new HttpMessageParser(MessageKind.Request);

        Assert.Empty(p.Append(Encoding.ASCII.GetBytes("this is not http at all\r\n\r\n")));

        var done = p.Append(B("GET /recovered HTTP/1.1\nContent-Length: 0\n\n"));
        Assert.Equal("/recovered", Assert.Single(done).Target);
    }

    [Fact]
    public void Resynchronises_onto_the_next_message_after_corruption()
    {
        // What a lost segment actually looks like: the tail of one message's start line
        // glued straight onto the head of the next.
        var raw = Encoding.ASCII.GetBytes(
            "HTTP/1.1 2ent-Length: 20\r\n\r\n01234567890123456789" +
            "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok");

        var done = new HttpMessageParser(MessageKind.Response).Append(raw);

        var m = Assert.Single(done);
        Assert.Equal(201, m.StatusCode);
        Assert.Equal("ok", Body(m));
    }

    [Fact]
    public void Noise_alone_never_spins_the_parser()
    {
        var p = new HttpMessageParser(MessageKind.Request);

        for (var i = 0; i < 50; i++)
        {
            Assert.Empty(p.Append(Encoding.ASCII.GetBytes("junk junk junk\r\n")));
        }

        // Still able to parse a real request afterwards.
        Assert.Single(p.Append(B("GET /fine HTTP/1.1\nContent-Length: 0\n\n")));
    }

    [Fact]
    public void Counts_every_byte_it_was_given()
    {
        var raw = B("GET /x HTTP/1.1\nContent-Length: 0\n\n");
        var p = new HttpMessageParser(MessageKind.Request);
        p.Append(raw);

        Assert.Equal((long)raw.Length, p.BytesSeen);
    }

    // --- Regression: findings from the adversarial review of the parser ---

    [Fact]
    public void A_body_that_decompresses_past_the_cap_is_flagged_truncated()
    {
        // Compressed body sits under the 1 MB wire cap, but inflates past the 8 MB
        // decompression cap. It must be reported cut-short, not silently complete.
        var payload = new byte[9 * 1024 * 1024];
        for (var i = 0; i < payload.Length; i++) { payload[i] = (byte)'a'; }

        byte[] gz;
        using (var ms = new MemoryStream())
        {
            using (var g = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            {
                g.Write(payload, 0, payload.Length);
            }
            gz = ms.ToArray();
        }

        Assert.True(gz.Length < 1024 * 1024, "compressed body must fit under the wire cap");

        var head = B($"HTTP/1.1 200 OK\nContent-Encoding: gzip\nContent-Length: {gz.Length}\n\n");
        var all = new byte[head.Length + gz.Length];
        Buffer.BlockCopy(head, 0, all, 0, head.Length);
        Buffer.BlockCopy(gz, 0, all, head.Length, gz.Length);

        var m = Assert.Single(new HttpMessageParser(MessageKind.Response).Append(all));

        Assert.True(m.BodyDecompressed);
        Assert.True(m.BodyTruncated);                 // the fix: no longer silently complete
        Assert.Equal(8 * 1024 * 1024, m.Body.Length);
    }

    [Fact]
    public void A_1xx_interim_response_does_not_consume_the_head_no_body_flag()
    {
        // HEAD request: caller marks the next response as body-less. The server sends an
        // interim 103 first. The flag must survive to the real 200, which advertises a
        // Content-Length it will never send a body for.
        var p = new HttpMessageParser(MessageKind.Response) { NextResponseHasNoBody = true };

        var done = p.Append(B(
            "HTTP/1.1 103 Early Hints\nLink: </style.css>; rel=preload\n\n" +
            "HTTP/1.1 200 OK\nContent-Length: 500\n\n"));

        Assert.Equal(2, done.Count);
        Assert.Equal(103, done[0].StatusCode);
        Assert.Equal(200, done[1].StatusCode);
        Assert.Empty(done[1].Body);                   // the fix: 200 framed as body-less
        Assert.False(p.HasPartialMessage);            // not stuck waiting for 500 phantom bytes
    }

    [Fact]
    public void Chunked_trailers_cannot_grow_the_header_list_without_bound()
    {
        var p = new HttpMessageParser(MessageKind.Response, maxHeaderBytes: 1024);

        var sb = new System.Text.StringBuilder("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n3\nabc\n0\n");
        for (var i = 0; i < 200; i++) { sb.Append($"X-Pad-{i}: {new string('z', 40)}\n"); }
        sb.Append("\n");

        var done = p.Append(B(sb.ToString()));

        var m = Assert.Single(done);
        Assert.Equal("abc", Body(m));
        Assert.True(m.Headers.Count < 200, $"trailer flood not capped: {m.Headers.Count} headers");
    }

}

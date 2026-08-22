using System.Net;
using System.Text;
using Portmirror.Agent.Capture;
using Portmirror.Agent.Pcap;
using Portmirror.Agent.Redaction;
using Xunit;

namespace Portmirror.Tests;

public class TcpFlowReassemblerTests
{
    private const string Client = "10.0.0.1";
    private const string Server = "10.0.0.2";

    private static TcpSegment Seg(
        string sip, int sp, string dip, int dp, uint seq, string payload,
        bool syn = false, bool ack = false, bool fin = false, bool rst = false) => new()
    {
        Source = new Endpoint(IPAddress.Parse(sip), sp),
        Destination = new Endpoint(IPAddress.Parse(dip), dp),
        Sequence = seq,
        Syn = syn, Ack = ack, Fin = fin, Rst = rst,
        Payload = Encoding.ASCII.GetBytes(payload)
    };

    private static TcpFlowReassembler New() =>
        new(new Redactor(true), serverPorts: new[] { 80 });

    private static string? Body(HttpMessage? m) => m?.Body;

    [Fact]
    public void Pairs_a_request_with_its_response()
    {
        var r = New();
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1000, "", syn: true)));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 2000, "", syn: true, ack: true)));
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1001, "GET /orders HTTP/1.1\r\nHost: h\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 2001, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")));

        var ex = Assert.Single(got);
        Assert.Equal("GET", ex.Verb);
        Assert.Equal("/orders", ex.Url);
        Assert.Equal(200, ex.StatusCode);
        Assert.Equal(CaptureTier.PacketCapture, ex.Tier);
        Assert.Equal(Client, ex.ClientIp);
        Assert.Equal("hi", Body(ex.Response));
        Assert.False(ex.Partial);
    }

    [Fact]
    public void Reassembles_a_request_whose_segments_arrive_out_of_order()
    {
        var r = New();
        const string req = "POST /pay HTTP/1.1\r\nContent-Length: 5\r\n\r\nmoney";
        var half = req.Length / 2;
        var got = new List<Exchange>();

        // The SYN fixes the initial sequence number, which is what lets out-of-order recovery
        // work — a real capture sees the handshake. (Without a SYN the first segment seen defines
        // the stream start, an unavoidable limit of mid-stream capture.)
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 999, "", syn: true)));

        // Second half first, then the first half — data starts at ISN + 1 = 1000.
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, (uint)(1000 + half), req[half..])));
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1000, req[..half])));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 2000, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")));

        var ex = Assert.Single(got);
        Assert.Equal("POST", ex.Verb);
        Assert.Equal("/pay", ex.Url);
        Assert.Equal(201, ex.StatusCode);
        Assert.Equal("money", Body(ex.Request));
    }

    [Fact]
    public void Determines_direction_from_a_server_port_hint_without_a_syn()
    {
        var r = New();   // serverPorts = {80}
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, "GET /a HTTP/1.1\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")));

        var ex = Assert.Single(got);
        Assert.Equal("/a", ex.Url);
        Assert.Equal(Client, ex.ClientIp);
    }

    [Fact]
    public void Falls_back_to_treating_the_first_destination_as_the_server()
    {
        var r = new TcpFlowReassembler(new Redactor(true));   // no server-port hint
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 9999, 1, "GET /b HTTP/1.1\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 9999, Client, 5000, 1, "HTTP/1.1 204 No Content\r\n\r\n")));

        var ex = Assert.Single(got);
        Assert.Equal("/b", ex.Url);
        Assert.Equal(204, ex.StatusCode);
        Assert.Equal(Client, ex.ClientIp);
    }

    [Fact]
    public void Pairs_two_transactions_on_a_keep_alive_connection_in_order()
    {
        var r = New();
        const string req1 = "GET /1 HTTP/1.1\r\nHost: h\r\n\r\n";
        const string req2 = "GET /2 HTTP/1.1\r\nHost: h\r\n\r\n";
        const string res1 = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA";
        const string res2 = "HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nB";
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, req1)));
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, (uint)(1 + req1.Length), req2)));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, res1)));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, (uint)(1 + res1.Length), res2)));

        Assert.Equal(2, got.Count);
        Assert.Equal("/1", got[0].Url);
        Assert.Equal(200, got[0].StatusCode);
        Assert.Equal("A", Body(got[0].Response));
        Assert.Equal("/2", got[1].Url);
        Assert.Equal(404, got[1].StatusCode);
        Assert.Equal("B", Body(got[1].Response));
    }

    [Fact]
    public void A_head_request_frames_its_response_as_body_less()
    {
        var r = New();
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, "HEAD /page HTTP/1.1\r\nHost: h\r\n\r\n")));
        // Advertises a length it will never send a body for, then the next response follows.
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")));

        var ex = Assert.Single(got);
        Assert.Equal("HEAD", ex.Verb);
        Assert.Equal(200, ex.StatusCode);
        Assert.Null(Body(ex.Response));   // empty body maps to null, not a phantom 1234-byte read
    }

    [Fact]
    public void A_request_with_no_response_surfaces_as_partial_on_close()
    {
        var r = New();
        var key = FlowKey.For(new Endpoint(IPAddress.Parse(Client), 5000), new Endpoint(IPAddress.Parse(Server), 80));

        Assert.Empty(r.Accept(Seg(Client, 5000, Server, 80, 1, "GET /lonely HTTP/1.1\r\nHost: h\r\n\r\n")));

        var closed = r.CloseFlow(key);

        var ex = Assert.Single(closed);
        Assert.Equal("/lonely", ex.Url);
        Assert.True(ex.Partial);
        Assert.NotNull(ex.Request);
        Assert.Null(ex.Response);
    }

    [Fact]
    public void A_reset_closes_the_flow_and_flushes()
    {
        var r = New();
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, "GET /x HTTP/1.1\r\nHost: h\r\n\r\n")));
        Assert.Equal(1, r.FlowCount);

        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "", rst: true)));

        Assert.Equal(0, r.FlowCount);   // flow torn down
        var ex = Assert.Single(got);
        Assert.True(ex.Partial);        // request never answered
        Assert.Equal("/x", ex.Url);
    }

    [Fact]
    public void Redacts_a_card_number_in_the_request_url()
    {
        var r = New();
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, "GET /pay?pan=4111111111111111 HTTP/1.1\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")));

        var ex = Assert.Single(got);
        Assert.DoesNotContain("4111111111111111", ex.Url);
    }

    [Fact]
    public void End_to_end_from_a_pcapng_file_to_a_paired_exchange()
    {
        var reqFrame = PacketBuilders.Ethernet(0x0800,
            PacketBuilders.Ipv4Tcp(Client, 5000, Server, 80, 1,
                Encoding.ASCII.GetBytes("GET /p HTTP/1.1\r\nHost: h\r\n\r\n")));
        var resFrame = PacketBuilders.Ethernet(0x0800,
            PacketBuilders.Ipv4Tcp(Server, 80, Client, 5000, 1,
                Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc")));

        var file = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[] { reqFrame, resFrame });

        var r = New();
        var got = new List<Exchange>();
        foreach (var packet in PcapngReader.Read(file))
        {
            var seg = PacketParser.Parse(packet.LinkType, packet.Data);
            if (seg is not null)
            {
                got.AddRange(r.Accept(seg));
            }
        }

        var ex = Assert.Single(got);
        Assert.Equal("GET", ex.Verb);
        Assert.Equal("/p", ex.Url);
        Assert.Equal(200, ex.StatusCode);
        Assert.Equal("abc", Body(ex.Response));
        Assert.Equal("text/plain", ex.Response!.ContentType);
    }

    // --- Regression: findings from the adversarial review of the reassembler ---

    [Fact]
    public void Pipelined_get_then_head_frames_each_response_correctly()
    {
        var r = New();
        const string req1 = "GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
        const string req2 = "HEAD /b HTTP/1.1\r\nHost: h\r\n\r\n";
        const string res1 = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        const string res2 = "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n";   // HEAD: no body sent
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 999, "", syn: true)));
        // Both requests pipelined before any response.
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1000, req1)));
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, (uint)(1000 + req1.Length), req2)));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 2000, res1)));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, (uint)(2000 + res1.Length), res2)));

        Assert.Equal(2, got.Count);
        Assert.Equal("/a", got[0].Url);
        Assert.Equal("abc", Body(got[0].Response));   // GET kept its body
        Assert.Equal("/b", got[1].Url);
        Assert.Equal("HEAD", got[1].Verb);
        Assert.Null(Body(got[1].Response));            // HEAD framed body-less, not a 500-byte phantom
    }

    [Fact]
    public void A_new_connection_reusing_the_four_tuple_is_captured_not_dropped()
    {
        var r = New();
        var got = new List<Exchange>();

        // First connection, ISN 1000.
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1000, "", syn: true)));
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1001, "GET /first HTTP/1.1\r\nHost: h\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 2001, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")));

        // Same 4-tuple reused by a brand-new connection with a different ISN.
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 8000, "", syn: true)));
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 8001, "GET /second HTTP/1.1\r\nHost: h\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 9001, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB")));

        var urls = got.Where(e => e.Url is not null).Select(e => e.Url).ToList();
        Assert.Contains("/first", urls);
        Assert.Contains("/second", urls);   // the second connection was NOT dropped
    }

    [Fact]
    public void A_retransmitted_syn_does_not_reset_the_flow()
    {
        var r = New();
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1000, "", syn: true)));
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1000, "", syn: true)));   // same ISN = retransmit
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1001, "GET /x HTTP/1.1\r\nHost: h\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 2001, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")));

        var ex = Assert.Single(got);
        Assert.Equal("/x", ex.Url);
        Assert.False(ex.Partial);
    }

    [Fact]
    public void A_backlog_of_unanswered_requests_is_bounded_and_flushed_as_partial()
    {
        var r = New();
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 999, "", syn: true)));

        // Many requests, no responses (a lossy or one-sided capture). The queue must not grow
        // without bound; the oldest are flushed as partial.
        uint seq = 1000;
        for (var i = 0; i < 600; i++)
        {
            var req = $"GET /{i} HTTP/1.1\r\nHost: h\r\n\r\n";
            got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, seq, req)));
            seq += (uint)req.Length;
        }

        var partials = got.Where(e => e.Partial && e.Request is not null && e.Response is null).ToList();
        Assert.NotEmpty(partials);                 // bounding kicked in
        Assert.Equal("/0", partials[0].Url);       // oldest flushed first
    }


    // --- Direction tagging (inbound vs outbound), from the local host's IPs ---

    private static TcpFlowReassembler WithLocal(params string[] localIps) =>
        new(new Redactor(true), serverPorts: new[] { 80 }, localIps: localIps);

    [Fact]
    public void An_inbound_request_is_tagged_inbound()
    {
        // The local host is 10.0.0.2, the server side of the flow — someone called in.
        var r = WithLocal(Server);
        var got = new List<Exchange>();
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, "GET /in HTTP/1.1\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")));

        Assert.Equal(CaptureDirection.Inbound, Assert.Single(got).Direction);
    }

    [Fact]
    public void An_outbound_call_is_tagged_outbound()
    {
        // The local host is 10.0.0.1, the client side — it made a server-to-server call out.
        var r = WithLocal(Client);
        var got = new List<Exchange>();
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, "POST /downstream HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")));

        var ex = Assert.Single(got);
        Assert.Equal(CaptureDirection.Outbound, ex.Direction);
        Assert.Equal("/downstream", ex.Url);
    }

    [Fact]
    public void Direction_is_unknown_when_no_local_ips_are_known()
    {
        var r = New();   // no localIps
        var got = new List<Exchange>();
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, "GET /x HTTP/1.1\r\n\r\n")));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")));

        Assert.Equal(CaptureDirection.Unknown, Assert.Single(got).Direction);
    }

    [Fact]
    public void Recovers_the_next_transaction_stranded_behind_a_capture_gap()
    {
        var r = New();
        const string req1 = "GET /1 HTTP/1.1\r\nHost: h\r\n\r\n";
        const string res1 = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA";
        const string req2 = "GET /2 HTTP/1.1\r\nHost: h\r\n\r\n";
        const string res2 = "HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nB";
        var got = new List<Exchange>();

        // The handshake fixes both initial sequence numbers.
        r.Accept(Seg(Client, 5000, Server, 80, 1000, "", syn: true));
        r.Accept(Seg(Server, 80, Client, 5000, 5000, "", syn: true, ack: true));

        // The first transaction is captured whole and pairs.
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1001, req1)));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 5001, res1)));
        Assert.Single(got);

        // A capture restart drops the bytes in flight: the next request and response each arrive
        // 50 bytes further on than their direction expects, so both sit buffered behind a hole
        // and nothing is emitted — this is the keep-alive stranding that killed the yield.
        var stranded = new List<Exchange>();
        stranded.AddRange(r.Accept(Seg(Client, 5000, Server, 80, (uint)(1001 + req1.Length + 50), req2)));
        stranded.AddRange(r.Accept(Seg(Server, 80, Client, 5000, (uint)(5001 + res1.Length + 50), res2)));
        Assert.Empty(stranded);

        // Recovery skips the hole in both directions and releases the stranded transaction.
        var recovered = r.RecoverStalled();
        var ex = Assert.Single(recovered);
        Assert.Equal("/2", ex.Url);
        Assert.Equal(404, ex.StatusCode);
        Assert.Equal("B", Body(ex.Response));
        Assert.False(ex.Partial);
    }

    [Fact]
    public void A_dropped_request_does_not_mispair_later_responses_when_the_flow_closes()
    {
        var r = New();
        const string req0 = "GET /0 HTTP/1.1\r\nHost: h\r\n\r\n";
        const string req2 = "GET /2 HTTP/1.1\r\nHost: h\r\n\r\n";   // same length as req0
        const string res0 = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA";
        const string res1 = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB";   // same length as res0
        const string res2 = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nC";
        var L = (uint)req0.Length;
        var M = (uint)res0.Length;
        var got = new List<Exchange>();

        r.Accept(Seg(Client, 5000, Server, 80, 1000, "", syn: true));
        r.Accept(Seg(Server, 80, Client, 5000, 5000, "", syn: true, ack: true));

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1001, req0)));               // req0
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 5001, res0)));               // res0 -> pairs
        // req1 (at 1001 + L) is dropped entirely — the outbound packet never captured.
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 5001 + M, res1)));            // res1 (its request is gone)
        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1001 + 2 * L, req2)));        // req2 -> stranded behind the hole
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 5001 + 2 * M, res2)));        // res2

        // Before the connection closes, only req0/res0 has paired.
        Assert.Single(got.Where(e => !e.Partial));

        got.AddRange(r.Flush());

        // Exactly one complete pair overall. The dropped request left the queues a different
        // length; pairing FIFO across that would confidently pair req2 with res1 — a wrong body on
        // the wrong request. It must stay one complete pair.
        var complete = got.Where(e => !e.Partial).ToList();
        var only = Assert.Single(complete);
        Assert.Equal("/0", only.Url);
        Assert.Equal("A", Body(only.Response));

        // The stranded request is still recovered and surfaced — as a request-only partial, not
        // mispaired and not lost.
        Assert.Contains(got, e => e.Partial && e.Url == "/2" && e.Response is null);

        // Both orphaned responses surface as response-only partials.
        Assert.Equal(2, got.Count(e => e.Partial && e.Verb is null && e.Response is not null));
    }

    [Fact]
    public void A_flow_making_normal_progress_is_left_untouched_by_recovery()
    {
        var r = New();
        const string req1 = "GET /1 HTTP/1.1\r\nHost: h\r\n\r\n";
        var got = new List<Exchange>();

        got.AddRange(r.Accept(Seg(Client, 5000, Server, 80, 1, req1)));
        got.AddRange(r.Accept(Seg(Server, 80, Client, 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")));
        Assert.Single(got);

        // The head of a second request, contiguous with the stream: nothing is buffered behind a
        // gap, it simply has not all arrived yet.
        r.Accept(Seg(Client, 5000, Server, 80, (uint)(1 + req1.Length), "POST /2 HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"));

        // Recovery must not fire on it — an in-progress message is not a stranded one, and
        // flushing it here would emit a bogus partial and desync the queues.
        Assert.Empty(r.RecoverStalled());
    }

}

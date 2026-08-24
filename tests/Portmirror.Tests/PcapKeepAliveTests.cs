using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Portmirror.Agent.Capture;
using Portmirror.Agent.Pcap;
using Portmirror.Agent.Redaction;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// Reproduces the real field case: a keep-alive server-to-server connection carrying many
/// GET/chunked-200 pairs, captured the way the live feed captures it — with pktmon's <c>--comp all</c>
/// duplicating every packet, and across interval-window boundaries. The whole flow is generic
/// (RFC-5737 test addresses, no real hosts) so it is safe to keep in the repo.
/// </summary>
public class PcapKeepAliveTests
{
    private const string Client = "198.51.100.10";
    private const int ClientPort = 50000;
    private const string Server = "203.0.113.20";
    private const int ServerPort = 4040;

    private static byte[] Frame(byte[] ip) => PacketBuilders.Ethernet(0x0800, ip);

    /// <summary>Handshake + <paramref name="n"/> GET/chunked-200 pairs on one keep-alive connection,
    /// then a graceful close. When <paramref name="duplicate"/> is set, every frame is emitted twice
    /// back to back, as pktmon's --comp all does.</summary>
    private static List<byte[]> BuildFlow(int n, bool duplicate)
    {
        var frames = new List<byte[]>();
        void Add(byte[] f) { frames.Add(f); if (duplicate) { frames.Add(f.ToArray()); } }

        uint cseq = 1000, sseq = 5000;
        Add(Frame(PacketBuilders.Ipv4Tcp(Client, ClientPort, Server, ServerPort, cseq, System.Array.Empty<byte>(), syn: true))); cseq += 1;
        Add(Frame(PacketBuilders.Ipv4Tcp(Server, ServerPort, Client, ClientPort, sseq, System.Array.Empty<byte>(), syn: true, ack: true))); sseq += 1;
        Add(Frame(PacketBuilders.Ipv4Tcp(Client, ClientPort, Server, ServerPort, cseq, System.Array.Empty<byte>(), ack: true)));

        for (var i = 0; i < n; i++)
        {
            var req = Encoding.ASCII.GetBytes("GET /api/version HTTP/1.1\r\nHost: svc\r\n\r\n");
            Add(Frame(PacketBuilders.Ipv4Tcp(Client, ClientPort, Server, ServerPort, cseq, req, ack: true)));
            cseq += (uint)req.Length;

            var json = "{\"ok\":true,\"i\":" + i + "}";
            var resp = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n"
                + json.Length.ToString("x") + "\r\n" + json + "\r\n0\r\n\r\n");
            Add(Frame(PacketBuilders.Ipv4Tcp(Server, ServerPort, Client, ClientPort, sseq, resp, ack: true)));
            sseq += (uint)resp.Length;
        }

        // Graceful close (both FINs), which is what flushes any still-queued messages.
        Add(Frame(PacketBuilders.Ipv4Tcp(Client, ClientPort, Server, ServerPort, cseq, System.Array.Empty<byte>(), ack: true, fin: true)));
        Add(Frame(PacketBuilders.Ipv4Tcp(Server, ServerPort, Client, ClientPort, sseq, System.Array.Empty<byte>(), ack: true, fin: true)));
        return frames;
    }

    private static PcapProcessor NewProcessor() =>
        new(new Redactor(false), new[] { ServerPort }, new[] { Client });

    private static (int paired, int reqOnly, int respOnly) Classify(IEnumerable<Exchange> all)
    {
        var list = all.ToList();
        return (
            list.Count(e => e.Request is not null && e.Response is not null),
            list.Count(e => e.Request is not null && e.Response is null),
            list.Count(e => e.Request is null && e.Response is not null));
    }

    [Fact]
    public void KeepAlive_clean_capture_pairs_every_request_with_its_response()
    {
        var proc = NewProcessor();
        var ex = proc.Process(PacketBuilders.Pcapng(1, BuildFlow(10, duplicate: false))).ToList();
        ex.AddRange(proc.RecoverStalled());

        var (paired, reqOnly, respOnly) = Classify(ex);
        Assert.True(paired == 10, $"expected 10 paired, got paired={paired} reqOnly={reqOnly} respOnly={respOnly}");
        Assert.All(ex.Where(e => e.Response is not null), e => Assert.Equal(200, e.StatusCode));
    }

    [Fact]
    public void KeepAlive_with_comp_all_duplication_still_pairs_every_request()
    {
        var proc = NewProcessor();
        var ex = proc.Process(PacketBuilders.Pcapng(1, BuildFlow(10, duplicate: true))).ToList();
        ex.AddRange(proc.RecoverStalled());

        var (paired, reqOnly, respOnly) = Classify(ex);
        Assert.True(paired == 10, $"expected 10 paired, got paired={paired} reqOnly={reqOnly} respOnly={respOnly}");
    }

    [Fact]
    public void KeepAlive_split_across_interval_windows_still_pairs_every_request()
    {
        var frames = BuildFlow(10, duplicate: false);
        var half = frames.Count / 2;

        var proc = NewProcessor();
        var ex = new List<Exchange>();
        ex.AddRange(proc.Process(PacketBuilders.Pcapng(1, frames.Take(half))));
        ex.AddRange(proc.RecoverStalled());                       // the interval loop runs this each window
        ex.AddRange(proc.Process(PacketBuilders.Pcapng(1, frames.Skip(half))));
        ex.AddRange(proc.RecoverStalled());

        var (paired, reqOnly, respOnly) = Classify(ex);
        Assert.True(paired == 10, $"expected 10 paired, got paired={paired} reqOnly={reqOnly} respOnly={respOnly}");
    }

    private static byte[] LoadFixture(string name)
    {
        var asm = typeof(PcapKeepAliveTests).Assembly;
        using var s = asm.GetManifestResourceStream(name)
                      ?? throw new InvalidOperationException($"embedded fixture '{name}' not found");
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// The real thing: a capture taken off a CORE box exactly as the live feed takes it (pktmon
    /// --comp all, so every packet is duplicated), of 15 keep-alive GETs to a plaintext service.
    /// One request packet was dropped on the wire, so requests and responses are slightly
    /// asymmetric — the case that was surfacing requests with no response. Responses must pair,
    /// not vanish.
    /// </summary>
    [Fact]
    public void RealCompAllCapture_pairs_requests_with_their_responses()
    {
        var proc = NewProcessor();
        var ex = proc.Process(LoadFixture("keepalive-compall.pcapng")).ToList();
        ex.AddRange(proc.RecoverStalled());

        var (paired, reqOnly, respOnly) = Classify(ex);
        var withResponse = ex.Count(e => e.Response is not null);
        Assert.True(paired >= 13 && withResponse >= 13,
            $"responses should pair with their requests: paired={paired} reqOnly={reqOnly} respOnly={respOnly} withResponse={withResponse}");
    }
}

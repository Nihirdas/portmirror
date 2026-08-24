using System.Text;
using Portmirror.Agent.Pcap;
using Portmirror.Agent.Redaction;
using Xunit;

namespace Portmirror.Tests;

public class PcapProcessorTests
{
    private static byte[] Frame(string sip, int sp, string dip, int dp, uint seq, string payload) =>
        PacketBuilders.Ethernet(0x0800,
            PacketBuilders.Ipv4Tcp(sip, sp, dip, dp, seq, Encoding.ASCII.GetBytes(payload)));

    [Fact]
    public void Processes_a_pcapng_file_into_a_paired_exchange()
    {
        var file = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[]
        {
            Frame("10.0.0.1", 5000, "10.0.0.2", 80, 1, "GET /p HTTP/1.1\r\nHost: h\r\n\r\n"),
            Frame("10.0.0.2", 80, "10.0.0.1", 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
        });

        var processor = new PcapProcessor(new Redactor(true), new[] { 80 });
        var got = processor.Process(file);

        var ex = Assert.Single(got);
        Assert.Equal("GET", ex.Verb);
        Assert.Equal("http://h/p", ex.Url);
        Assert.Equal(200, ex.StatusCode);
        Assert.Equal("abc", ex.Response!.Body);
        Assert.True(processor.PacketsSeen >= 2);
        Assert.True(processor.SegmentsSeen >= 2);
    }

    [Fact]
    public void Keeps_one_flow_across_two_files_so_a_split_connection_reassembles()
    {
        var processor = new PcapProcessor(new Redactor(true), new[] { 80 });

        // Request in the first file, its response in the second — a connection spanning intervals.
        var file1 = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[]
        {
            Frame("10.0.0.1", 5000, "10.0.0.2", 80, 1, "GET /split HTTP/1.1\r\nHost: h\r\n\r\n")
        });
        var file2 = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[]
        {
            Frame("10.0.0.2", 80, "10.0.0.1", 5000, 1, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        });

        Assert.Empty(processor.Process(file1));   // request seen, no response yet
        var got = processor.Process(file2);

        var ex = Assert.Single(got);
        Assert.Equal("http://h/split", ex.Url);
        Assert.Equal("ok", ex.Response!.Body);
    }

    [Fact]
    public void Recovers_a_flow_stranded_across_two_files()
    {
        var processor = new PcapProcessor(new Redactor(true), new[] { 80 });

        const string req1 = "GET /1 HTTP/1.1\r\nHost: h\r\n\r\n";
        const string res1 = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA";
        const string req2 = "GET /2 HTTP/1.1\r\nHost: h\r\n\r\n";
        const string res2 = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB";

        // A keep-alive connection: one whole transaction in the first capture file.
        var file1 = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[]
        {
            Frame("10.0.0.1", 5000, "10.0.0.2", 80, 1, req1),
            Frame("10.0.0.2", 80, "10.0.0.1", 5000, 1, res1)
        });
        // The next transaction lands in the second file, but the stop/start gap between windows
        // dropped the bytes in between, so each direction resumes 40 bytes past where it left off.
        var file2 = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[]
        {
            Frame("10.0.0.1", 5000, "10.0.0.2", 80, (uint)(1 + req1.Length + 40), req2),
            Frame("10.0.0.2", 80, "10.0.0.1", 5000, (uint)(1 + res1.Length + 40), res2)
        });

        Assert.Single(processor.Process(file1));   // first transaction pairs
        Assert.Empty(processor.Process(file2));     // second is stranded behind the gap
        var recovered = processor.RecoverStalled();

        var ex = Assert.Single(recovered);
        Assert.Equal("http://h/2", ex.Url);
        Assert.Equal("B", ex.Response!.Body);
        Assert.False(ex.Partial);
    }

    [Fact]
    public void An_empty_file_yields_nothing_and_does_not_throw()
    {
        var processor = new PcapProcessor(new Redactor(true));
        Assert.Empty(processor.Process(Array.Empty<byte>()));
    }

    [Fact]
    public void Flush_surfaces_a_request_with_no_response_as_partial()
    {
        var processor = new PcapProcessor(new Redactor(true), new[] { 80 });
        var file = PacketBuilders.Pcapng(PacketParser.LinkTypeEthernet, new[]
        {
            Frame("10.0.0.1", 5000, "10.0.0.2", 80, 1, "GET /lonely HTTP/1.1\r\nHost: h\r\n\r\n")
        });

        Assert.Empty(processor.Process(file));

        var flushed = processor.Flush();
        var ex = Assert.Single(flushed);
        Assert.Equal("http://h/lonely", ex.Url);
        Assert.True(ex.Partial);
    }
}

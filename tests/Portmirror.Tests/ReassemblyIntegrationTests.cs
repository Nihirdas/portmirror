using System.Text;
using Portmirror.Agent.Http;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// The assembler and the parser have to work as a pair: captured segments arrive scrambled, and
/// the parser only ever sees an ordered stream. These are the cases that matter in the field.
/// </summary>
public class ReassemblyIntegrationTests
{
    private static byte[] Wire(string s) => Encoding.ASCII.GetBytes(s.Replace("\n", "\r\n"));

    private static List<(uint seq, byte[] data)> Slice(byte[] raw, uint start, int size)
    {
        var parts = new List<(uint, byte[])>();

        for (var offset = 0; offset < raw.Length; offset += size)
        {
            var len = Math.Min(size, raw.Length - offset);
            var chunk = new byte[len];
            Array.Copy(raw, offset, chunk, 0, len);
            parts.Add((unchecked(start + (uint)offset), chunk));
        }

        return parts;
    }

    private static List<ParsedMessage> Run(IEnumerable<(uint seq, byte[] data)> segments, MessageKind kind)
    {
        var assembler = new TcpStreamAssembler(1000);
        var parser = new HttpMessageParser(kind);
        var done = new List<ParsedMessage>();

        foreach (var (seq, data) in segments)
        {
            var ordered = assembler.Add(seq, data);
            if (ordered.Length > 0)
            {
                done.AddRange(parser.Append(ordered));
            }
        }

        return done;
    }

    [Fact]
    public void A_chunked_response_survives_being_captured_out_of_order()
    {
        var raw = Wire(
            "HTTP/1.1 200 OK\nContent-Type: application/json\nTransfer-Encoding: chunked\n\n" +
            "1a\n{\"orders\":[{\"id\":8841,\n" +
            "18\n\"total\":42.50}]}\n" +
            "0\n\n");

        var segments = Slice(raw, 1000, 16);
        Assert.True(segments.Count > 3, "test needs several segments to shuffle");

        // Reverse the arrival order entirely — the worst realistic case.
        segments.Reverse();

        var done = Run(segments, MessageKind.Response);
        var m = Assert.Single(done);

        Assert.Equal(200, m.StatusCode);
        Assert.Equal("{\"orders\":[{\"id\":8841,\"total\":42.50}]}", Encoding.UTF8.GetString(m.Body));
    }

    [Fact]
    public void Retransmitted_segments_do_not_duplicate_body_bytes()
    {
        var raw = Wire("POST /api/orders HTTP/1.1\nContent-Length: 11\n\nhello world");
        var segments = Slice(raw, 1000, 8);

        // Send everything twice, interleaved.
        var doubled = new List<(uint, byte[])>();
        foreach (var s in segments)
        {
            doubled.Add(s);
            doubled.Add(s);
        }

        var m = Assert.Single(Run(doubled, MessageKind.Request));
        Assert.Equal("hello world", Encoding.UTF8.GetString(m.Body));
    }

    [Fact]
    public void Pipelined_requests_split_correctly_even_when_segments_are_shuffled()
    {
        var raw = Wire(
            "POST /first HTTP/1.1\nContent-Length: 5\n\naaaaa" +
            "POST /second HTTP/1.1\nContent-Length: 3\n\nbbb");

        var segments = Slice(raw, 1000, 12);
        // Rotate rather than reverse, so the stream fills gaps in an awkward order.
        var rotated = segments.Skip(2).Concat(segments.Take(2)).ToList();

        var done = Run(rotated, MessageKind.Request);

        Assert.Equal(2, done.Count);
        Assert.Equal("/first", done[0].Target);
        Assert.Equal("aaaaa", Encoding.UTF8.GetString(done[0].Body));
        Assert.Equal("/second", done[1].Target);
        Assert.Equal("bbb", Encoding.UTF8.GetString(done[1].Body));
    }

    [Fact]
    public void A_dropped_segment_costs_one_message_not_the_whole_connection()
    {
        // Two responses back to back on a keep-alive connection, with a segment of the first
        // one lost in capture — the everyday failure mode for packet capture.
        var first = Wire("HTTP/1.1 200 OK\nContent-Length: 20\n\n01234567890123456789");
        var second = Wire("HTTP/1.1 201 Created\nContent-Length: 2\n\nok");
        var raw = first.Concat(second).ToArray();
        var segments = Slice(raw, 1000, 10);

        var assembler = new TcpStreamAssembler(1000);
        var parser = new HttpMessageParser(MessageKind.Response);
        var done = new List<ParsedMessage>();

        for (var i = 0; i < segments.Count; i++)
        {
            if (i == 1)
            {
                continue;   // this segment never arrives
            }

            var ordered = assembler.Add(segments[i].seq, segments[i].data);
            if (ordered.Length > 0)
            {
                done.AddRange(parser.Append(ordered));
            }
        }

        // Nothing can be delivered while the stream waits on a hole that will never fill.
        Assert.Empty(done);
        Assert.True(assembler.PendingSegments > 0);

        done.AddRange(parser.Append(assembler.SkipGap()));

        Assert.True(assembler.DiscardedBytes > 0, "the lost bytes should be accounted for");

        // The damaged message is unrecoverable, but the parser resynchronises and the one
        // behind it arrives intact.
        Assert.Contains(done, m => m.StatusCode == 201 && Encoding.UTF8.GetString(m.Body) == "ok");
    }
}

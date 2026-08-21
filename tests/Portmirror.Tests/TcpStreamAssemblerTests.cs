using System.Text;
using Portmirror.Agent.Http;
using Xunit;

namespace Portmirror.Tests;

public class TcpStreamAssemblerTests
{
    private static byte[] B(string s) => Encoding.ASCII.GetBytes(s);
    private static string S(byte[] b) => Encoding.ASCII.GetString(b);

    [Fact]
    public void In_order_segments_pass_straight_through()
    {
        var a = new TcpStreamAssembler(1000);

        Assert.Equal("abc", S(a.Add(1000, B("abc"))));
        Assert.Equal("de", S(a.Add(1003, B("de"))));
        Assert.Equal(5L, a.DeliveredBytes);
        Assert.Equal(0, a.PendingSegments);
    }

    [Fact]
    public void An_early_arrival_waits_for_the_gap_in_front_of_it()
    {
        var a = new TcpStreamAssembler(100);

        Assert.Empty(a.Add(103, B("DEF")));
        Assert.Equal(1, a.PendingSegments);

        Assert.Equal("ABCDEF", S(a.Add(100, B("ABC"))));
        Assert.Equal(0, a.PendingSegments);
    }

    [Fact]
    public void Several_buffered_segments_drain_at_once_when_the_gap_closes()
    {
        var a = new TcpStreamAssembler(0);

        a.Add(6, B("ghi"));
        a.Add(3, B("def"));
        a.Add(9, B("jkl"));
        Assert.Equal(3, a.PendingSegments);

        Assert.Equal("abcdefghijkl", S(a.Add(0, B("abc"))));
        Assert.Equal(0, a.PendingSegments);
    }

    [Fact]
    public void A_pure_retransmit_is_discarded()
    {
        var a = new TcpStreamAssembler(500);
        a.Add(500, B("hello"));

        Assert.Empty(a.Add(500, B("hello")));
        Assert.Equal(5L, a.DiscardedBytes);
        Assert.Equal(5L, a.DeliveredBytes);
    }

    [Fact]
    public void A_partly_overlapping_segment_contributes_only_its_new_tail()
    {
        var a = new TcpStreamAssembler(0);
        a.Add(0, B("abcde"));

        // Re-sends "cde" and adds "fg".
        Assert.Equal("fg", S(a.Add(2, B("cdefg"))));
        Assert.Equal(7L, a.DeliveredBytes);
    }

    [Fact]
    public void An_empty_segment_is_ignored()
    {
        var a = new TcpStreamAssembler(0);

        Assert.Empty(a.Add(0, Array.Empty<byte>()));
        Assert.Equal(0u, a.NextSequence);
    }

    [Fact]
    public void Skipping_a_gap_releases_what_came_after_it()
    {
        var a = new TcpStreamAssembler(0);
        a.Add(0, B("abc"));
        a.Add(10, B("xyz"));      // bytes 3..9 never arrived

        Assert.Empty(a.Add(20, Array.Empty<byte>()));

        var released = a.SkipGap();
        Assert.Equal("xyz", S(released));
        Assert.Equal(7L, a.DiscardedBytes);
        Assert.Equal(0, a.PendingSegments);
    }

    [Fact]
    public void Skipping_with_nothing_buffered_yields_nothing()
    {
        Assert.Empty(new TcpStreamAssembler(0).SkipGap());
    }

    [Fact]
    public void Survives_sequence_number_wraparound()
    {
        // Start four bytes below the 32-bit ceiling so the stream wraps mid-message.
        var start = uint.MaxValue - 3;
        var a = new TcpStreamAssembler(start);

        Assert.Equal("abcd", S(a.Add(start, B("abcd"))));
        Assert.Equal("efgh", S(a.Add(unchecked(start + 4), B("efgh"))));
        Assert.Equal(8L, a.DeliveredBytes);
    }

    [Fact]
    public void Buffers_across_the_wraparound_too()
    {
        var start = uint.MaxValue - 1;
        var a = new TcpStreamAssembler(start);

        Assert.Empty(a.Add(unchecked(start + 2), B("second")));
        Assert.Equal("XYsecond", S(a.Add(start, B("XY"))));
    }

    [Theory]
    [InlineData(10u, 4u, 6)]
    [InlineData(4u, 10u, -6)]
    [InlineData(0u, 0u, 0)]
    public void Sequence_arithmetic_is_signed_and_wrap_safe(uint a, uint b, int expected)
    {
        Assert.Equal(expected, TcpStreamAssembler.Delta(a, b));
    }

    [Fact]
    public void Delta_is_correct_across_the_ceiling()
    {
        Assert.Equal(2, TcpStreamAssembler.Delta(1u, unchecked(uint.MaxValue)));
    }

    [Fact]
    public void Refuses_to_buffer_beyond_its_memory_cap()
    {
        var a = new TcpStreamAssembler(0, maxBufferedBytes: 4096);

        for (var i = 0; i < 64; i++)
        {
            a.Add((uint)(1000 + i * 1000), new byte[1000]);
        }

        Assert.True(a.PendingBytes <= 4096, $"buffered {a.PendingBytes} bytes");
        Assert.True(a.DiscardedBytes > 0);
    }

    // --- Regression: findings from the adversarial review of the reassembly layer ---

    [Fact]
    public void A_resegmented_retransmit_does_not_strand_an_earlier_out_of_order_segment()
    {
        // Buffer a future segment, then deliver a superset retransmit that covers it entirely.
        // The stale buffered copy must not linger — if it does, SkipGap later walks the stream
        // backwards onto already-delivered bytes and wedges the connection.
        var a = new TcpStreamAssembler(0);
        a.Add(10, B("WORLD"));                 // future, buffered
        Assert.Equal(1, a.PendingSegments);

        var delivered = a.Add(0, B("abcdefghijklmnopqrst"));  // 20-byte superset of 0..19
        Assert.Equal("abcdefghijklmnopqrst", S(delivered));
        Assert.Equal(0, a.PendingSegments);    // the stale [10,"WORLD"] must be gone
        Assert.Equal(0, a.PendingBytes);
        Assert.Equal(20u, a.NextSequence);
    }

    [Fact]
    public void SkipGap_never_moves_the_stream_position_backwards()
    {
        var a = new TcpStreamAssembler(0);
        a.Add(0, B("abcdefghijklmnopqrst"));   // delivers 0..19, _next = 20
        a.Add(10, B("WORLD"));                 // wholly in the past now

        var released = a.SkipGap();

        Assert.Empty(released);                // nothing ahead of the stream to release
        Assert.Equal(20u, a.NextSequence);     // must not rewind to 10
        Assert.Equal(0, a.PendingSegments);
    }

    [Fact]
    public void SkipGap_still_jumps_forward_over_a_genuine_gap()
    {
        var a = new TcpStreamAssembler(0);
        a.Add(0, B("abc"));                    // delivers 0..2, _next = 3
        a.Add(10, B("xyz"));                   // bytes 3..9 never arrived

        var released = a.SkipGap();

        Assert.Equal("xyz", S(released));
        Assert.Equal(13u, a.NextSequence);
    }

    [Fact]
    public void A_refused_same_key_replacement_leaves_the_byte_count_consistent()
    {
        // The cap refuses an oversized replacement of an existing key. The counter must not
        // drift: a drift here permanently loosens the memory cap.
        var a = new TcpStreamAssembler(0, maxBufferedBytes: 4096);
        a.Add(100, new byte[2000]);
        a.Add(3000, new byte[1500]);
        Assert.Equal(3500, a.PendingBytes);

        a.Add(3000, new byte[2500]);           // 3500 - 1500 + 2500 = 4500 > 4096 → refused

        Assert.Equal(3500, a.PendingBytes);    // old 1500 entry kept; counter unchanged
        Assert.True(a.PendingBytes >= 0);
    }

    [Fact]
    public void Byte_count_stays_non_negative_and_true_after_a_refused_replacement_drains()
    {
        var a = new TcpStreamAssembler(0, maxBufferedBytes: 4096);
        a.Add(100, new byte[2000]);
        a.Add(3000, new byte[1500]);
        a.Add(3000, new byte[2500]);           // refused

        // Fill the gap so everything buffered drains; the count must return exactly to zero,
        // never negative (which would let the cap buffer past its limit forever).
        a.Add(0, new byte[100]);               // _next 0..99
        a.Add(100, new byte[2900]);            // reaches 3000, draining the 1500 there too

        Assert.True(a.PendingBytes >= 0, $"buffered went negative: {a.PendingBytes}");
        Assert.Equal(0, a.PendingSegments);
        Assert.Equal(0, a.PendingBytes);
    }

}

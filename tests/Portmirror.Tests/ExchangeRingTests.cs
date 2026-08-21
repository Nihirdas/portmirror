using Portmirror.Agent.Capture;
using Portmirror.Agent.Storage;
using Xunit;

namespace Portmirror.Tests;

public class ExchangeRingTests
{
    private static Exchange Make(string url) => new() { Url = url, StartedUtc = DateTimeOffset.UnixEpoch };

    [Fact]
    public void Append_assigns_monotonic_sequences_starting_at_one()
    {
        var ring = new ExchangeRing(8);

        Assert.Equal(1L, ring.Append(Make("/a")));
        Assert.Equal(2L, ring.Append(Make("/b")));
        Assert.Equal(3L, ring.Append(Make("/c")));
        Assert.Equal(3L, ring.LastSeq);
        Assert.Equal(3, ring.Count);
    }

    [Fact]
    public void Since_returns_only_newer_entries_oldest_first()
    {
        var ring = new ExchangeRing(8);
        ring.Append(Make("/a"));
        ring.Append(Make("/b"));
        ring.Append(Make("/c"));

        var page = ring.Since(1, 10);

        Assert.Equal(new[] { "/b", "/c" }, page.Select(e => e.Url!).ToArray());
    }

    [Fact]
    public void Since_respects_limit()
    {
        var ring = new ExchangeRing(8);
        for (var i = 0; i < 5; i++)
        {
            ring.Append(Make($"/{i}"));
        }

        Assert.Equal(2, ring.Since(0, 2).Count);
    }

    [Fact]
    public void Overwrites_oldest_once_full_but_keeps_sequence_running()
    {
        var ring = new ExchangeRing(3);
        for (var i = 1; i <= 5; i++)
        {
            ring.Append(Make($"/{i}"));
        }

        Assert.Equal(3, ring.Count);
        Assert.Equal(3, ring.Capacity);
        Assert.Equal(5L, ring.LastSeq);
        Assert.Equal(new[] { "/5", "/4", "/3" }, ring.Latest(10).Select(e => e.Url!).ToArray());
    }

    [Fact]
    public void Latest_is_newest_first()
    {
        var ring = new ExchangeRing(8);
        ring.Append(Make("/old"));
        ring.Append(Make("/new"));

        Assert.Equal("/new", ring.Latest(10)[0].Url!);
    }

    [Fact]
    public void Filter_is_applied()
    {
        var ring = new ExchangeRing(8);
        ring.Append(Make("/keep"));
        ring.Append(Make("/drop"));

        var found = ring.Latest(10, e => e.Url == "/keep");

        Assert.Single(found);
        Assert.Equal("/keep", found[0].Url!);
    }

    [Fact]
    public void ById_finds_and_Clear_empties()
    {
        var ring = new ExchangeRing(4);
        var one = Make("/x");
        ring.Append(one);

        Assert.NotNull(ring.ById(one.Id));
        Assert.Null(ring.ById("nope"));

        ring.Clear();

        Assert.Equal(0, ring.Count);
        Assert.Null(ring.ById(one.Id));
    }

    [Fact]
    public void Rejects_nonsense_capacity()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ExchangeRing(0));
    }
}

using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

public class ExchangeCorrelatorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 21, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Completes_once_the_response_status_is_known()
    {
        var correlator = new ExchangeCorrelator();
        const string id = "req-1";

        Assert.Null(correlator.Accept(new EtwSignal(id, SignalKind.RequestReceived, T0, ClientIp: "10.0.0.9")));
        Assert.Null(correlator.Accept(new EtwSignal(id, SignalKind.Delivered, T0.AddMilliseconds(2),
            Url: "/api/pay", QueueName: "app-pool")));

        var done = correlator.Accept(new EtwSignal(id, SignalKind.ResponseSent, T0.AddMilliseconds(9),
            Verb: "POST", StatusCode: 500));

        Assert.NotNull(done);
        Assert.Equal("POST", done!.Verb!);
        Assert.Equal("/api/pay", done.Url!);
        Assert.Equal(500, done.StatusCode!.Value);
        Assert.Equal("10.0.0.9", done.ClientIp!);
        Assert.Equal("app-pool", done.QueueName!);
        Assert.Equal(9d, done.DurationMs!.Value);
        Assert.False(done.Partial);
        Assert.Equal(0, correlator.PendingCount);
    }

    [Fact]
    public void A_response_without_a_status_does_not_complete_anything()
    {
        var correlator = new ExchangeCorrelator();

        correlator.Accept(new EtwSignal("r", SignalKind.RequestReceived, T0));

        // FastRespLast carries only a RequestId, so the outcome is still unknown.
        Assert.Null(correlator.Accept(new EtwSignal("r", SignalKind.ResponseSent, T0.AddMilliseconds(3))));
        Assert.Equal(1, correlator.PendingCount);
    }

    [Fact]
    public void Trailing_events_do_not_produce_a_duplicate_exchange()
    {
        var correlator = new ExchangeCorrelator();
        const string id = "req-2";

        correlator.Accept(new EtwSignal(id, SignalKind.RequestReceived, T0));
        var done = correlator.Accept(new EtwSignal(id, SignalKind.ResponseSent, T0.AddMilliseconds(5),
            StatusCode: 200));

        Assert.NotNull(done);

        // HTTP.SYS keeps emitting for a finished request: FastRespLast, FastSend, SendComplete.
        Assert.Null(correlator.Accept(new EtwSignal(id, SignalKind.ResponseSent, T0.AddMilliseconds(6), StatusCode: 200)));
        Assert.Null(correlator.Accept(new EtwSignal(id, SignalKind.RequestEnded, T0.AddMilliseconds(7), StatusCode: 200)));

        Assert.Equal(0, correlator.PendingCount);
        Assert.Empty(correlator.Sweep(T0.AddMilliseconds(8)));
    }

    [Fact]
    public void Completes_on_an_explicit_terminal_event_even_with_no_status()
    {
        var correlator = new ExchangeCorrelator();

        correlator.Accept(new EtwSignal("t", SignalKind.RequestReceived, T0, Url: "/dropped"));
        var done = correlator.Accept(new EtwSignal("t", SignalKind.RequestEnded, T0.AddMilliseconds(4)));

        Assert.NotNull(done);
        Assert.Null(done!.StatusCode);
        Assert.False(done.Partial);
    }

    [Fact]
    public void A_cache_hit_terminates_the_exchange()
    {
        var correlator = new ExchangeCorrelator();

        correlator.Accept(new EtwSignal("c1", SignalKind.RequestReceived, T0));
        var done = correlator.Accept(new EtwSignal("c1", SignalKind.CacheServed, T0.AddMilliseconds(2),
            StatusCode: 200));

        Assert.NotNull(done);
        Assert.Equal(200, done!.StatusCode!.Value);
    }

    [Fact]
    public void Identity_fields_are_not_overwritten_by_later_nulls()
    {
        var correlator = new ExchangeCorrelator();

        correlator.Accept(new EtwSignal("x", SignalKind.RequestParsed, T0, Verb: "GET", Url: "/first"));
        correlator.Accept(new EtwSignal("x", SignalKind.Delivered, T0.AddMilliseconds(1)));
        var done = correlator.Accept(new EtwSignal("x", SignalKind.RequestEnded, T0.AddMilliseconds(2)));

        Assert.Equal("GET", done!.Verb!);
        Assert.Equal("/first", done.Url!);
    }

    [Fact]
    public void Unterminated_requests_are_flushed_as_partial_once_idle()
    {
        var correlator = new ExchangeCorrelator(idleTimeout: TimeSpan.FromSeconds(10));
        correlator.Accept(new EtwSignal("p1", SignalKind.RequestReceived, T0, Url: "/hang"));

        Assert.Empty(correlator.Sweep(T0.AddSeconds(5)));
        Assert.Equal(1, correlator.PendingCount);

        var flushed = correlator.Sweep(T0.AddSeconds(11));

        Assert.Single(flushed);
        Assert.True(flushed[0].Partial);
        Assert.Equal("/hang", flushed[0].Url!);
        Assert.Equal(0, correlator.PendingCount);
    }

    [Fact]
    public void Finished_ids_are_forgotten_so_the_id_can_be_reused()
    {
        var correlator = new ExchangeCorrelator(idleTimeout: TimeSpan.FromSeconds(10));

        correlator.Accept(new EtwSignal("reused", SignalKind.RequestReceived, T0));
        Assert.NotNull(correlator.Accept(new EtwSignal("reused", SignalKind.ResponseSent, T0, StatusCode: 200)));
        Assert.Equal(1, correlator.RecentlyCompletedCount);

        correlator.Sweep(T0.AddSeconds(30));
        Assert.Equal(0, correlator.RecentlyCompletedCount);

        // HTTP.SYS recycles request ids, so a later request under the same id must be captured.
        correlator.Accept(new EtwSignal("reused", SignalKind.RequestReceived, T0.AddSeconds(31), Url: "/again"));
        var second = correlator.Accept(new EtwSignal("reused", SignalKind.ResponseSent, T0.AddSeconds(31), StatusCode: 404));

        Assert.NotNull(second);
        Assert.Equal("/again", second!.Url!);
        Assert.Equal(404, second.StatusCode!.Value);
    }

    [Fact]
    public void Concurrent_requests_do_not_bleed_into_each_other()
    {
        var correlator = new ExchangeCorrelator();

        correlator.Accept(new EtwSignal("a", SignalKind.RequestParsed, T0, Verb: "GET", Url: "/a"));
        correlator.Accept(new EtwSignal("b", SignalKind.RequestParsed, T0, Verb: "POST", Url: "/b"));

        var a = correlator.Accept(new EtwSignal("a", SignalKind.ResponseSent, T0.AddMilliseconds(5), StatusCode: 200));
        var b = correlator.Accept(new EtwSignal("b", SignalKind.ResponseSent, T0.AddMilliseconds(6), StatusCode: 201));

        Assert.Equal("/a", a!.Url!);
        Assert.Equal("/b", b!.Url!);
        Assert.Equal(200, a.StatusCode!.Value);
        Assert.Equal(201, b.StatusCode!.Value);
    }

    [Fact]
    public void Signals_without_a_correlation_id_are_dropped()
    {
        var correlator = new ExchangeCorrelator();

        Assert.Null(correlator.Accept(new EtwSignal(string.Empty, SignalKind.RequestReceived, T0)));
        Assert.Equal(0, correlator.PendingCount);
    }

    [Fact]
    public void Pending_set_stays_bounded_when_requests_never_finish()
    {
        var correlator = new ExchangeCorrelator(maxPending: 10);

        for (var i = 0; i < 50; i++)
        {
            correlator.Accept(new EtwSignal($"id{i}", SignalKind.RequestReceived, T0.AddMilliseconds(i)));
        }

        Assert.True(correlator.PendingCount <= 11, $"pending grew to {correlator.PendingCount}");
    }

    [Fact]
    public void Replays_the_real_Server_2022_lifecycle_end_to_end()
    {
        // The exact sequence and field availability read off build 20348 via the agent's own
        // diagnostics endpoint. Parse is absent because it is keyed by RequestObj rather than
        // RequestId, and FastResp is where the status and verb actually arrive.
        var correlator = new ExchangeCorrelator();
        const string requestId = "-216172781040040931";

        Assert.Null(correlator.Accept(new EtwSignal(requestId, SignalKind.Other, T0)));               // ConnIdAssgn
        Assert.Null(correlator.Accept(new EtwSignal(requestId, SignalKind.RequestReceived,
            T0.AddMilliseconds(1), ClientIp: "10.0.0.5")));                                       // RecvReq
        Assert.Null(correlator.Accept(new EtwSignal(requestId, SignalKind.Delivered,
            T0.AddMilliseconds(2), Url: "http://10.0.0.5:4040/api/version?pm=1",
            SiteId: "1017903699", QueueName: "example-site")));                             // Deliver

        var done = correlator.Accept(new EtwSignal(requestId, SignalKind.ResponseSent,
            T0.AddMilliseconds(9), Verb: "GET", StatusCode: 200));                                     // FastResp

        Assert.NotNull(done);
        Assert.Equal("GET", done!.Verb!);
        Assert.Equal("http://10.0.0.5:4040/api/version?pm=1", done.Url!);
        Assert.Equal(200, done.StatusCode!.Value);
        Assert.Equal("example-site", done.QueueName!);
        Assert.Equal("10.0.0.5", done.ClientIp!);
        Assert.False(done.Partial);

        // Trailing FastRespLast / FastSend / SendComplete must not add a second row.
        Assert.Null(correlator.Accept(new EtwSignal(requestId, SignalKind.ResponseSent, T0.AddMilliseconds(10))));
        Assert.Null(correlator.Accept(new EtwSignal(requestId, SignalKind.RequestEnded, T0.AddMilliseconds(11))));
    }
}

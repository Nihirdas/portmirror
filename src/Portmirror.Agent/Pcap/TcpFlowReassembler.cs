using Portmirror.Agent.Capture;
using Portmirror.Agent.Http;
using Portmirror.Agent.Redaction;

namespace Portmirror.Agent.Pcap;

/// <summary>
/// Turns a stream of captured TCP segments into paired HTTP exchanges. It demultiplexes segments
/// into connections, reorders each direction with a <see cref="TcpStreamAssembler"/>, frames whole
/// messages with a <see cref="HttpMessageParser"/>, and pairs each request with its response in
/// order. Redaction runs through <see cref="MessageMapper"/>, so nothing unmasked ever leaves here.
///
/// Everything it produces is tagged <see cref="CaptureTier.PacketCapture"/> and, being packet-based,
/// it cannot see same-host (loopback) traffic — that is the IIS module tier's job.
/// </summary>
public sealed class TcpFlowReassembler
{
    private sealed class Flow
    {
        public Endpoint Client;
        public Endpoint Server;
        public bool DirectionKnown;

        public TcpStreamAssembler? ClientToServer;
        public TcpStreamAssembler? ServerToClient;
        public readonly HttpMessageParser RequestParser = new(MessageKind.Request);
        public readonly HttpMessageParser ResponseParser = new(MessageKind.Response);

        public readonly Queue<ParsedMessage> Requests = new();
        public readonly Queue<ParsedMessage> Responses = new();

        public bool ClientFinished;
        public bool ServerFinished;
        public int PairIndex;
    }

    private readonly Redactor _redactor;
    private readonly HashSet<int> _serverPorts;
    private readonly int _maxFlows;
    private readonly Dictionary<FlowKey, Flow> _flows = new();
    private readonly LinkedList<FlowKey> _order = new();   // insertion order, for eviction

    public TcpFlowReassembler(Redactor redactor, IEnumerable<int>? serverPorts = null, int maxFlows = 4096)
    {
        _redactor = redactor;
        _serverPorts = serverPorts is null ? new HashSet<int>() : new HashSet<int>(serverPorts);
        _maxFlows = maxFlows < 1 ? 1 : maxFlows;
    }

    public int FlowCount => _flows.Count;

    /// <summary>Folds one segment in and returns any exchanges it completed.</summary>
    public IReadOnlyList<Exchange> Accept(TcpSegment segment)
    {
        ArgumentNullException.ThrowIfNull(segment);

        var key = FlowKey.For(segment.Source, segment.Destination);

        if (!_flows.TryGetValue(key, out var flow))
        {
            flow = new Flow();
            _flows[key] = flow;
            _order.AddLast(key);
            EvictIfNeeded();
        }

        EstablishDirection(flow, segment);

        var isClientToServer = segment.Source.Equals(flow.Client);
        var emitted = new List<Exchange>();

        RouteSegment(flow, segment, isClientToServer);
        Pair(flow, key, emitted);

        // A reset tears the connection down; a graceful close needs both FINs.
        if (segment.Rst)
        {
            CloseInto(flow, key, emitted);
        }
        else if (segment.Fin)
        {
            if (isClientToServer) { flow.ClientFinished = true; } else { flow.ServerFinished = true; }
            if (flow.ClientFinished && flow.ServerFinished)
            {
                CloseInto(flow, key, emitted);
            }
        }

        return emitted;
    }

    /// <summary>Closes one flow, flushing any partial messages. Use on an idle or reset connection.</summary>
    public IReadOnlyList<Exchange> CloseFlow(FlowKey key)
    {
        var emitted = new List<Exchange>();
        if (_flows.TryGetValue(key, out var flow))
        {
            CloseInto(flow, key, emitted);
        }

        return emitted;
    }

    /// <summary>Closes every open flow. Use when capture stops.</summary>
    public IReadOnlyList<Exchange> Flush()
    {
        var emitted = new List<Exchange>();
        foreach (var key in _flows.Keys.ToList())
        {
            CloseInto(_flows[key], key, emitted);
        }

        return emitted;
    }

    private void EstablishDirection(Flow flow, TcpSegment seg)
    {
        if (flow.DirectionKnown)
        {
            return;
        }

        // SYN is the definitive signal; a SYN without ACK comes from the client, a SYN+ACK from
        // the server. Failing that, a known server port decides it; failing that, assume the
        // side being connected to (the destination of the first segment) is the server.
        if (seg.Syn && !seg.Ack)
        {
            flow.Client = seg.Source;
            flow.Server = seg.Destination;
        }
        else if (seg.Syn && seg.Ack)
        {
            flow.Server = seg.Source;
            flow.Client = seg.Destination;
        }
        else if (_serverPorts.Contains(seg.Source.Port))
        {
            flow.Server = seg.Source;
            flow.Client = seg.Destination;
        }
        else if (_serverPorts.Contains(seg.Destination.Port))
        {
            flow.Server = seg.Destination;
            flow.Client = seg.Source;
        }
        else
        {
            flow.Client = seg.Source;
            flow.Server = seg.Destination;
        }

        flow.DirectionKnown = true;
    }

    private void RouteSegment(Flow flow, TcpSegment seg, bool isClientToServer)
    {
        // A SYN consumes one sequence number; data begins at ISN+1. Seeding from the SYN is what
        // makes out-of-order recovery possible. On a mid-stream capture with no SYN the first
        // segment seen necessarily defines the start — earlier, lower-sequence bytes cannot be
        // recovered because nothing established where the stream truly began.
        var initialSeq = seg.Syn ? seg.Sequence + 1 : seg.Sequence;

        if (isClientToServer)
        {
            flow.ClientToServer ??= new TcpStreamAssembler(initialSeq);
            FeedRequest(flow, flow.ClientToServer.Add(seg.Sequence, seg.Payload));
        }
        else
        {
            flow.ServerToClient ??= new TcpStreamAssembler(initialSeq);
            FeedResponse(flow, flow.ServerToClient.Add(seg.Sequence, seg.Payload));
        }
    }

    private void FeedRequest(Flow flow, byte[] ordered)
    {
        if (ordered.Length == 0)
        {
            return;
        }

        foreach (var message in flow.RequestParser.Append(ordered))
        {
            flow.Requests.Enqueue(message);

            // A HEAD response carries no body however it is framed; tell the response parser so
            // it does not read the advertised Content-Length off the following response.
            if (string.Equals(message.Method, "HEAD", StringComparison.OrdinalIgnoreCase))
            {
                flow.ResponseParser.NextResponseHasNoBody = true;
            }
        }
    }

    private void FeedResponse(Flow flow, byte[] ordered)
    {
        if (ordered.Length == 0)
        {
            return;
        }

        foreach (var message in flow.ResponseParser.Append(ordered))
        {
            flow.Responses.Enqueue(message);
        }
    }

    private void Pair(Flow flow, FlowKey key, List<Exchange> emitted)
    {
        while (flow.Requests.Count > 0 && flow.Responses.Count > 0)
        {
            emitted.Add(BuildExchange(flow, key, flow.Requests.Dequeue(), flow.Responses.Dequeue(), partial: false));
        }
    }

    private void CloseInto(Flow flow, FlowKey key, List<Exchange> emitted)
    {
        // Release anything stranded behind a gap, then let each parser surface a final
        // partial message it was still assembling.
        if (flow.ClientToServer is not null) { FeedRequest(flow, flow.ClientToServer.SkipGap()); }
        if (flow.ServerToClient is not null) { FeedResponse(flow, flow.ServerToClient.SkipGap()); }

        var lastRequest = flow.RequestParser.Finish();
        if (lastRequest is not null) { flow.Requests.Enqueue(lastRequest); }

        var lastResponse = flow.ResponseParser.Finish();
        if (lastResponse is not null) { flow.Responses.Enqueue(lastResponse); }

        Pair(flow, key, emitted);

        // Whatever is left is unmatched: a request that never got an answer, or a response with
        // no captured request. Both are worth surfacing, flagged partial.
        while (flow.Requests.Count > 0)
        {
            emitted.Add(BuildExchange(flow, key, flow.Requests.Dequeue(), null, partial: true));
        }

        while (flow.Responses.Count > 0)
        {
            emitted.Add(BuildExchange(flow, key, null, flow.Responses.Dequeue(), partial: true));
        }

        _flows.Remove(key);
        _order.Remove(key);
    }

    private Exchange BuildExchange(Flow flow, FlowKey key, ParsedMessage? request, ParsedMessage? response, bool partial)
    {
        return new Exchange
        {
            CorrelationId = $"{key}#{flow.PairIndex++}",
            Tier = CaptureTier.PacketCapture,
            Partial = partial,
            ClientIp = flow.Client.Address?.ToString(),
            Verb = request?.Method,
            Url = _redactor.RedactUrl(request?.Target),
            StatusCode = response?.StatusCode,
            Request = request is null ? null : MessageMapper.ToHttpMessage(request, _redactor),
            Response = response is null ? null : MessageMapper.ToHttpMessage(response, _redactor)
        };
    }

    private void EvictIfNeeded()
    {
        while (_flows.Count > _maxFlows && _order.First is not null)
        {
            var oldest = _order.First.Value;
            _order.RemoveFirst();
            _flows.Remove(oldest);   // dropped without flushing: the alternative is unbounded memory
        }
    }
}

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
        public uint? ClientSyn;   // ISN of the client's SYN, to tell a reused 4-tuple from a retransmit
    }

    // A backlog this deep means one side of a connection is missing (loss or mid-stream capture),
    // so the oldest unmatched message is flushed as partial rather than held forever.
    private const int MaxQueuedPerDirection = 512;

    private readonly Redactor _redactor;
    private readonly HashSet<int> _serverPorts;
    private readonly HashSet<string> _localIps;
    private readonly int _maxFlows;
    private readonly Dictionary<FlowKey, Flow> _flows = new();
    private readonly LinkedList<FlowKey> _order = new();   // insertion order, for eviction

    public TcpFlowReassembler(
        Redactor redactor,
        IEnumerable<int>? serverPorts = null,
        IEnumerable<string>? localIps = null,
        int maxFlows = 4096)
    {
        _redactor = redactor;
        _serverPorts = serverPorts is null ? new HashSet<int>() : new HashSet<int>(serverPorts);
        _localIps = localIps is null
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(localIps, StringComparer.OrdinalIgnoreCase);
        _maxFlows = maxFlows < 1 ? 1 : maxFlows;
    }

    public int FlowCount => _flows.Count;

    /// <summary>Folds one segment in and returns any exchanges it completed.</summary>
    public IReadOnlyList<Exchange> Accept(TcpSegment segment)
    {
        ArgumentNullException.ThrowIfNull(segment);

        var key = FlowKey.For(segment.Source, segment.Destination);
        var emitted = new List<Exchange>();

        if (!_flows.TryGetValue(key, out var flow))
        {
            flow = CreateFlow(key);
        }

        // A SYN (without ACK) on an already-established flow is either a retransmit of the same
        // handshake or a new connection reusing the 4-tuple. If the ISN differs it is a new
        // connection: flush the old flow's partials and start fresh, or its data would be seeded
        // against the previous connection's sequence space and silently dropped.
        if (segment.Syn && !segment.Ack && flow.DirectionKnown
            && (flow.ClientSyn is null || flow.ClientSyn.Value != segment.Sequence))
        {
            CloseInto(flow, key, emitted);
            flow = CreateFlow(key);
        }

        EstablishDirection(flow, segment);

        var isClientToServer = segment.Source.Equals(flow.Client);

        RouteSegment(flow, segment, isClientToServer);
        Pair(flow, key, emitted);
        EnforceQueueBounds(flow, key, emitted);

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

    /// <summary>
    /// Releases flows stranded behind a capture gap, without closing them. Call this once after a
    /// whole capture file has been folded in: by then every segment in the file has been offered,
    /// so any bytes still buffered ahead of a hole can only be waiting on bytes that will never
    /// arrive — dropped in the stop/start gap between capture windows, or by the NIC. The peer
    /// already acknowledged them, so there is no wire retransmit to recapture.
    ///
    /// Without this, a keep-alive connection that loses bytes at one interval boundary strands
    /// every later message on it until the connection finally closes — which for a long-lived
    /// server-to-server connection may be never within a capture. This skips the hole and lets
    /// the flow keep producing exchanges.
    /// </summary>
    public IReadOnlyList<Exchange> RecoverStalled()
    {
        var emitted = new List<Exchange>();
        foreach (var (key, flow) in _flows)
        {
            var stalled = flow.ClientToServer is { PendingBytes: > 0 }
                          || flow.ServerToClient is { PendingBytes: > 0 };
            if (stalled)
            {
                // DrainGaps never adds or removes flows, so iterating _flows directly is safe.
                DrainGaps(flow, key, emitted);
            }
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
            flow.ClientSyn = seg.Sequence;
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

            // Record, in request order, whether this one was a HEAD. The response parser consumes
            // these in the same order, so pipelined mixes of HEAD and non-HEAD frame correctly.
            var isHead = string.Equals(message.Method, "HEAD", StringComparison.OrdinalIgnoreCase);
            flow.ResponseParser.ExpectResponse(isHead);
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
        // Release everything stranded behind any gap first — with parser resync, across every
        // hole — then let each parser surface the final partial message it was still assembling.
        // This is the same recovery the interval loop runs; a flow closed by FIN/RST mid-capture
        // (common in batch mode) reaches it only here.
        DrainGaps(flow, key, emitted);

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

    /// <summary>
    /// Recovers a flow stranded behind one or more capture gaps, leaving it open to carry on.
    /// First it skips every hole and releases the bytes buffered behind it, resynchronising each
    /// parser to the next message boundary — so both directions surface every message they still
    /// hold. Then it reconciles the two queues (see <see cref="Reconcile"/>).
    ///
    /// Skipping every hole before pairing is the point: a single dropped request packet strands
    /// every later request on the flow behind it in the assembler, so pairing before the skip sees
    /// only the responses and would flush them as orphans while their requests were still buffered.
    /// Releasing first lets the transactions after the gap pair up again.
    /// </summary>
    private void DrainGaps(Flow flow, FlowKey key, List<Exchange> emitted)
    {
        var guard = 0;
        var skipped = false;

        while (flow.ClientToServer is { PendingBytes: > 0 } || flow.ServerToClient is { PendingBytes: > 0 })
        {
            if (++guard > 4096)
            {
                break;
            }

            // Drop each half-parsed message; the released bytes begin mid-stream.
            flow.RequestParser.ResyncAfterGap();
            flow.ResponseParser.ResyncAfterGap();

            // Skip this hole and feed what followed. Requests first so their HEAD markers queue in
            // order before the responses that answer them are parsed. Each SkipGap moves the stream
            // strictly forward, so the bytes buffered behind a hole shrink every pass — this ends.
            if (flow.ClientToServer is not null) { FeedRequest(flow, flow.ClientToServer.SkipGap()); }
            if (flow.ServerToClient is not null) { FeedResponse(flow, flow.ServerToClient.SkipGap()); }
            skipped = true;
        }

        if (skipped)
        {
            Reconcile(flow, key, emitted);
        }
    }

    /// <summary>
    /// Pairs the two queues after a gap has been skipped. HTTP/1.1 answers a connection's requests
    /// in order, so once both directions are fully drained the only reason the queues differ in
    /// length is that a message's counterpart was dropped — and, order being preserved, that
    /// counterpart is the oldest unmatched entry on the longer side. Surface those as flagged
    /// partials, then the remainder lines up again and pairs correctly. A single lost packet
    /// therefore costs one exchange, not the rest of the connection, and never a mispair.
    ///
    /// Several interleaved drops within one recovery can still misalign; loss is surfaced as a
    /// flagged partial rather than hidden, so that shows up honestly rather than as a wrong body.
    /// </summary>
    private void Reconcile(Flow flow, FlowKey key, List<Exchange> emitted)
    {
        while (flow.Requests.Count > flow.Responses.Count)
        {
            emitted.Add(BuildExchange(flow, key, flow.Requests.Dequeue(), null, partial: true));
        }

        while (flow.Responses.Count > flow.Requests.Count)
        {
            emitted.Add(BuildExchange(flow, key, null, flow.Responses.Dequeue(), partial: true));
        }

        Pair(flow, key, emitted);
    }

    /// <summary>
    /// Outbound when the local host initiated the connection (it is the flow's client), inbound
    /// when the local host served it (it is the server). Unknown when neither side is local, which
    /// happens only if the capture sees traffic between two other hosts.
    /// </summary>
    private CaptureDirection DirectionOf(Flow flow)
    {
        if (_localIps.Count == 0)
        {
            return CaptureDirection.Unknown;
        }

        var clientLocal = flow.Client.Address is not null && _localIps.Contains(flow.Client.Address.ToString());
        var serverLocal = flow.Server.Address is not null && _localIps.Contains(flow.Server.Address.ToString());

        if (clientLocal && !serverLocal) { return CaptureDirection.Outbound; }
        if (serverLocal && !clientLocal) { return CaptureDirection.Inbound; }
        return CaptureDirection.Unknown;
    }

    private Exchange BuildExchange(Flow flow, FlowKey key, ParsedMessage? request, ParsedMessage? response, bool partial)
    {
        return new Exchange
        {
            CorrelationId = $"{key}#{flow.PairIndex++}",
            Tier = CaptureTier.PacketCapture,
            Direction = DirectionOf(flow),
            Partial = partial,
            ClientIp = flow.Client.Address?.ToString(),
            Verb = request?.Method,
            Url = _redactor.RedactUrl(request?.Target),
            StatusCode = response?.StatusCode,
            Request = request is null ? null : MessageMapper.ToHttpMessage(request, _redactor),
            Response = response is null ? null : MessageMapper.ToHttpMessage(response, _redactor)
        };
    }

    private Flow CreateFlow(FlowKey key)
    {
        var flow = new Flow();
        _flows[key] = flow;
        _order.AddLast(key);
        EvictIfNeeded();
        return flow;
    }

    /// <summary>
    /// Keeps the per-flow queues bounded. After pairing, at most one queue holds unmatched
    /// messages (the other is empty); flush its oldest as partial once the backlog is too deep,
    /// which also stops a stranded response from later mispairing with an unrelated request.
    /// </summary>
    private void EnforceQueueBounds(Flow flow, FlowKey key, List<Exchange> emitted)
    {
        while (flow.Requests.Count > MaxQueuedPerDirection)
        {
            emitted.Add(BuildExchange(flow, key, flow.Requests.Dequeue(), null, partial: true));
        }

        while (flow.Responses.Count > MaxQueuedPerDirection)
        {
            emitted.Add(BuildExchange(flow, key, null, flow.Responses.Dequeue(), partial: true));
        }
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

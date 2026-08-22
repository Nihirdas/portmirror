namespace Portmirror.Agent;

public sealed class AgentOptions
{
    public const string SectionName = "Portmirror";

    /// <summary>TCP port the agent's API and UI listen on.</summary>
    public int Port { get; set; } = 9099;

    /// <summary>How many exchanges to retain in memory. Oldest are overwritten.</summary>
    public int Capacity { get; set; } = 5000;

    /// <summary>Begin capturing as soon as the service starts.</summary>
    public bool AutoStartCapture { get; set; } = true;

    /// <summary>Mask card numbers, credentials and tokens. Leave this on.</summary>
    public bool RedactionEnabled { get; set; } = true;

    /// <summary>When set, /api/* requires this value in an X-Portmirror-Token header.</summary>
    public string? AuthToken { get; set; }

    /// <summary>How long to wait for a request's terminal event before flushing it as partial.</summary>
    public int IdleTimeoutSeconds { get; set; } = 30;

    /// <summary>Begin the packet-capture (body) feed at startup. Requires Windows + elevation.</summary>
    public bool PacketCaptureEnabled { get; set; }

    /// <summary>
    /// Length of each pktmon capture window, in seconds, before it is converted and processed.
    /// This is the latency-versus-completeness knob. Each window boundary is a brief capture
    /// restart, and a connection with bytes in flight across one loses them; a longer window means
    /// fewer boundaries, so fewer connections are cut — at the cost of taking that long to surface.
    /// (What is stranded behind a boundary is then recovered on the next window, so the loss is
    /// at most the one message straddling each boundary rather than the rest of the connection.)
    /// Set to 0 or less for batch mode: a single continuous capture, processed only when the feed
    /// stops. Batch mode has no boundaries at all, so it drops nothing, but shows nothing until
    /// stop — pktmon cannot convert a running capture.
    /// </summary>
    public int PacketIntervalSeconds { get; set; } = 30;

    /// <summary>
    /// Circular capture file size cap, in MB, per window. In batch mode this bounds the single
    /// continuous capture, so it is also the amount of history retained before the oldest is
    /// overwritten.
    /// </summary>
    public int PacketFileSizeMb { get; set; } = 50;

    /// <summary>Ports the agent should treat as servers, to classify direction and scope capture.</summary>
    public int[]? PacketServerPorts { get; set; }
}

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

    /// <summary>Seconds of capture per pktmon cycle before converting and processing.</summary>
    public int PacketIntervalSeconds { get; set; } = 5;

    /// <summary>Circular capture file size cap, in MB, per cycle.</summary>
    public int PacketFileSizeMb { get; set; } = 50;

    /// <summary>Ports the agent should treat as servers, to classify direction and scope capture.</summary>
    public int[]? PacketServerPorts { get; set; }
}

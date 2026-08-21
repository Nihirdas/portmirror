namespace Portmirror.Agent.Faults;

/// <summary>
/// One fault-injection rule: when an inbound request matches, the response is replaced with the
/// configured status (and optional body), and/or delayed. Rules let a tester exercise error paths
/// that are otherwise hard to trigger on demand — a 500 from a dependency, a slow upstream.
/// </summary>
public sealed class FaultRule
{
    public bool Enabled { get; set; } = true;

    /// <summary>Match this HTTP method, or any method when null/empty.</summary>
    public string? Method { get; set; }

    /// <summary>Match when the request path/query contains this text, or any path when null/empty.</summary>
    public string? PathContains { get; set; }

    /// <summary>Status to return instead of letting the request run.</summary>
    public int Status { get; set; } = 500;

    /// <summary>Optional replacement body.</summary>
    public string? Body { get; set; }

    /// <summary>Optional content type for the replacement body.</summary>
    public string? ContentType { get; set; }

    /// <summary>Delay applied before responding, in milliseconds. May be combined with a status.</summary>
    public int DelayMs { get; set; }
}

/// <summary>What to do to a matched request. A pure value, so matching stays testable.</summary>
public sealed class FaultDecision
{
    public int Status { get; init; }
    public string? Body { get; init; }
    public string? ContentType { get; init; }
    public int DelayMs { get; init; }

    /// <summary>True when only a delay is configured and the request should still run normally.</summary>
    public bool DelayOnly => Status <= 0;
}

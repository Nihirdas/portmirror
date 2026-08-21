namespace Portmirror.Agent.Capture;

/// <summary>
/// Normalised HTTP.SYS lifecycle events. Raw ETW event names and payload field names drift
/// between Windows builds, so the source layer maps into this shape and the correlator
/// only ever sees this — which keeps correlation unit-testable off a real ETW session.
/// </summary>
public enum SignalKind
{
    Other = 0,
    RequestReceived,
    RequestParsed,
    Delivered,
    ResponseSent,
    CacheServed,
    RequestEnded
}

public sealed record EtwSignal(
    string CorrelationId,
    SignalKind Kind,
    DateTimeOffset TimestampUtc,
    string? Verb = null,
    string? Url = null,
    int? StatusCode = null,
    string? ClientIp = null,
    string? SiteId = null,
    string? QueueName = null);

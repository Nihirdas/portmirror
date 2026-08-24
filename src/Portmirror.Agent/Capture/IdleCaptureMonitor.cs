using Microsoft.Extensions.Options;
using Portmirror.Agent.Pcap;

namespace Portmirror.Agent.Capture;

/// <summary>
/// Stops capture when no one is watching. A viewer (the dashboard, or the agent's own UI) polls the
/// listing/stream endpoints continuously; each poll is a heartbeat via <see cref="Touch"/>. If no
/// heartbeat arrives for <see cref="AgentOptions.IdleStopSeconds"/>, both tiers are stopped — so
/// capture runs only on demand and cleans itself up when the browser is closed, with no cooperation
/// needed from the client. Disabled (0) leaves capture running until it is stopped explicitly.
/// </summary>
public sealed class IdleCaptureMonitor : IHostedService, IDisposable
{
    private readonly EtwCaptureService _etw;
    private readonly IServiceProvider _services;
    private readonly AgentOptions _options;
    private readonly ILogger<IdleCaptureMonitor> _logger;

    private long _lastActivityTicks = DateTime.UtcNow.Ticks;
    private Timer? _timer;

    public IdleCaptureMonitor(
        EtwCaptureService etw,
        IServiceProvider services,
        IOptions<AgentOptions> options,
        ILogger<IdleCaptureMonitor> logger)
    {
        _etw = etw;
        _services = services;
        _options = options.Value;
        _logger = logger;
    }

    public int IdleStopSeconds => _options.IdleStopSeconds;

    public double SecondsSinceActivity =>
        (DateTime.UtcNow - new DateTime(Interlocked.Read(ref _lastActivityTicks), DateTimeKind.Utc)).TotalSeconds;

    /// <summary>Record viewer activity. Called on each listing/stream request.</summary>
    public void Touch() => Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);

    /// <summary>Pure decision so it can be unit-tested without a clock or a timer.</summary>
    internal static bool ShouldStop(bool anyCapturing, double secondsSinceActivity, int idleStopSeconds) =>
        idleStopSeconds > 0 && anyCapturing && secondsSinceActivity > idleStopSeconds;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.IdleStopSeconds > 0)
        {
            _timer = new Timer(_ => Check(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Change(Timeout.Infinite, Timeout.Infinite);
        return Task.CompletedTask;
    }

    private bool AnyCapturing() =>
        _etw.IsCapturing || (_services.GetService<PcapFeedService>()?.IsRunning ?? false);

    private void Check()
    {
        try
        {
            if (ShouldStop(AnyCapturing(), SecondsSinceActivity, _options.IdleStopSeconds))
            {
                _logger.LogInformation(
                    "No viewer activity for more than {Seconds}s — stopping capture.", _options.IdleStopSeconds);
                _etw.StopCapture();
                _services.GetService<PcapFeedService>()?.Stop();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Idle capture check failed.");
        }
    }

    public void Dispose() => _timer?.Dispose();
}

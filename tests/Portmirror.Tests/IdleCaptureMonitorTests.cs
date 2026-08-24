using Portmirror.Agent.Capture;
using Xunit;

namespace Portmirror.Tests;

/// <summary>
/// Capture stops when no viewer has polled for longer than the idle window — that is what makes it
/// on-demand and self-cleaning when a browser is closed.
/// </summary>
public class IdleCaptureMonitorTests
{
    [Fact]
    public void Disabled_never_stops()
    {
        Assert.False(IdleCaptureMonitor.ShouldStop(anyCapturing: true, secondsSinceActivity: 9999, idleStopSeconds: 0));
    }

    [Fact]
    public void Not_capturing_never_stops()
    {
        Assert.False(IdleCaptureMonitor.ShouldStop(anyCapturing: false, secondsSinceActivity: 9999, idleStopSeconds: 60));
    }

    [Fact]
    public void Recent_activity_keeps_capture_alive()
    {
        Assert.False(IdleCaptureMonitor.ShouldStop(anyCapturing: true, secondsSinceActivity: 30, idleStopSeconds: 60));
    }

    [Fact]
    public void Idle_beyond_the_window_stops()
    {
        Assert.True(IdleCaptureMonitor.ShouldStop(anyCapturing: true, secondsSinceActivity: 61, idleStopSeconds: 60));
    }
}

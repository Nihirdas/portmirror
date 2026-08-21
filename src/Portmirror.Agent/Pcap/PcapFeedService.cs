using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Portmirror.Agent.Capture;
using Portmirror.Agent.Redaction;
using Portmirror.Agent.Storage;

namespace Portmirror.Agent.Pcap;

/// <summary>
/// The Windows-only half of the packet feed. It drives pktmon in fixed intervals — capture,
/// convert to pcapng, hand the bytes to <see cref="PcapProcessor"/>, append the resulting
/// exchanges (with bodies) to the ring — then repeats. This is the tier that recovers request
/// and response payloads without a proxy and without an app-pool recycle.
///
/// It is off unless explicitly enabled: pktmon needs administrator rights, and packet capture is
/// blind to same-host traffic, so it complements rather than replaces the always-on ETW tier.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PcapFeedService
{
    private readonly ExchangeRing _ring;
    private readonly Redactor _redactor;
    private readonly AgentOptions _options;
    private readonly ILogger<PcapFeedService> _logger;

    private readonly object _sync = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private volatile bool _running;

    private long _filesProcessed;
    private long _exchangesEmitted;
    private long _packetsSeen;
    private string? _lastError;

    public PcapFeedService(
        ExchangeRing ring,
        Redactor redactor,
        IOptions<AgentOptions> options,
        ILogger<PcapFeedService> logger)
    {
        _ring = ring;
        _redactor = redactor;
        _options = options.Value;
        _logger = logger;
    }

    public bool IsRunning => _running;
    public long FilesProcessed => Interlocked.Read(ref _filesProcessed);
    public long ExchangesEmitted => Interlocked.Read(ref _exchangesEmitted);
    public long PacketsSeen => Interlocked.Read(ref _packetsSeen);
    public string? LastError => _lastError;

    /// <summary>Starts the capture loop. Returns the reason it could not start, or null on success.</summary>
    public string? TryStart()
    {
        lock (_sync)
        {
            if (_running)
            {
                return null;
            }

            if (!OperatingSystem.IsWindows())
            {
                return "Packet capture requires Windows.";
            }

            if (!Capture.EtwCaptureService.IsElevated())
            {
                return "Packet capture requires administrator rights (pktmon).";
            }

            if (!PktmonAvailable())
            {
                return "pktmon.exe was not found; it ships with Windows Server 2019 and later.";
            }

            _cts = new CancellationTokenSource();
            _running = true;
            _lastError = null;
            _loop = Task.Run(() => RunLoopAsync(_cts.Token));
            _logger.LogInformation("Packet feed started (pktmon, {Interval}s intervals).", _options.PacketIntervalSeconds);
            return null;
        }
    }

    public void Stop()
    {
        Task? loop;
        lock (_sync)
        {
            if (!_running)
            {
                return;
            }

            _running = false;
            _cts?.Cancel();
            loop = _loop;
            _loop = null;
        }

        try
        {
            loop?.Wait(TimeSpan.FromSeconds(15));
        }
        catch (AggregateException)
        {
            // Cancellation surfaces here; nothing to do.
        }

        SafeRun("stop", "stop");
        _logger.LogInformation("Packet feed stopped.");
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        var processor = new PcapProcessor(_redactor, _options.PacketServerPorts);
        var workDir = Path.Combine(Path.GetTempPath(), "portmirror-pcap");
        Directory.CreateDirectory(workDir);
        var etl = Path.Combine(workDir, "capture.etl");
        var pcap = Path.Combine(workDir, "capture.pcapng");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await CaptureOnceAsync(processor, etl, pcap, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _logger.LogWarning(ex, "Packet capture cycle failed; retrying.");
                await DelayQuietly(TimeSpan.FromSeconds(5), ct);
            }
        }

        AppendAll(processor.Flush());
        TryDelete(etl);
        TryDelete(pcap);
    }

    private async Task CaptureOnceAsync(PcapProcessor processor, string etl, string pcap, CancellationToken ct)
    {
        TryDelete(etl);
        TryDelete(pcap);

        // A short filtered capture: full packets, all components (so nothing is missed), bounded
        // file size. A per-port filter is applied when the operator has named the server ports,
        // which also keeps the agent's own outbound chatter out of the capture.
        var startArgs = $"start -c --pkt-size 0 --comp all --file-name \"{etl}\" --file-size {_options.PacketFileSizeMb}";
        ApplyPortFilters();
        SafeRun("filter add", FilterArgs());
        RunPktmon(startArgs);

        await DelayQuietly(TimeSpan.FromSeconds(Math.Max(1, _options.PacketIntervalSeconds)), ct);

        RunPktmon("stop");
        SafeRun("filter remove", "filter remove");

        if (!File.Exists(etl))
        {
            return;
        }

        RunPktmon($"etl2pcap \"{etl}\" -o \"{pcap}\"");
        if (!File.Exists(pcap))
        {
            return;
        }

        var bytes = await File.ReadAllBytesAsync(pcap, ct);
        Interlocked.Exchange(ref _packetsSeen, processor.PacketsSeen);
        AppendAll(processor.Process(bytes));
        Interlocked.Increment(ref _filesProcessed);
    }

    private void AppendAll(IReadOnlyList<Exchange> exchanges)
    {
        foreach (var exchange in exchanges)
        {
            // The reassembler leaves wall-clock time unset (it is deterministic); stamp it here.
            if (exchange.StartedUtc == default)
            {
                exchange.StartedUtc = DateTimeOffset.UtcNow;
            }

            exchange.CompletedUtc ??= exchange.StartedUtc;
            _ring.Append(exchange);
            Interlocked.Increment(ref _exchangesEmitted);
        }
    }

    private void ApplyPortFilters()
    {
        // Clear any filter a previous crashed cycle may have left behind.
        SafeRun("filter remove", "filter remove");
    }

    private string FilterArgs()
    {
        var ports = _options.PacketServerPorts;
        if (ports is null || ports.Length == 0)
        {
            // No hint: capture all TCP. (pktmon's default with no filter is all packets.)
            return "filter add portmirror -t TCP";
        }

        // pktmon takes one port per filter; the first named port is the common case.
        return $"filter add portmirror -t TCP -p {ports[0]}";
    }

    private bool PktmonAvailable()
    {
        try
        {
            return RunPktmon("status", throwOnError: false);
        }
        catch
        {
            return false;
        }
    }

    private bool RunPktmon(string arguments, bool throwOnError = true)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "pktmon.exe",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        process.Start();
        process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(30_000);

        if (process.ExitCode != 0 && throwOnError)
        {
            throw new InvalidOperationException($"pktmon {arguments} exited {process.ExitCode}: {stderr}");
        }

        return process.ExitCode == 0;
    }

    private void SafeRun(string what, string arguments)
    {
        try
        {
            RunPktmon(arguments, throwOnError: false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "pktmon {What} failed (ignored).", what);
        }
    }

    private static async Task DelayQuietly(TimeSpan delay, CancellationToken ct)
    {
        try
        {
            await Task.Delay(delay, ct);
        }
        catch (OperationCanceledException)
        {
            // Expected on stop.
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort; a locked temp file is harmless.
        }
    }
}

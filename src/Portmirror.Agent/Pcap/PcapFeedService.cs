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

        // Two capture files used in turn. Each interval the running one is stopped and the other
        // is started immediately, so the capture gap is a single stop->start (well under a second)
        // rather than the whole convert-and-process time; the just-closed file is processed only
        // after the new capture is already running.
        var etlA = Path.Combine(workDir, "capture-a.etl");
        var etlB = Path.Combine(workDir, "capture-b.etl");
        var pcap = Path.Combine(workDir, "snapshot.pcapng");

        // The filter is set once for the whole session, not per cycle, so it never widens the gap.
        SafeRun("filter remove", "filter remove");
        SafeRun("filter add", FilterArgs());

        TryDelete(etlA);
        var current = etlA;
        StartCapture(current);

        try
        {
            while (!ct.IsCancellationRequested)
            {
                await DelayQuietly(TimeSpan.FromSeconds(Math.Max(1, _options.PacketIntervalSeconds)), ct);
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                var closed = current;

                try
                {
                    RunPktmon("stop");                          // flush 'closed'  — gap opens
                    current = ReferenceEquals(closed, etlA) ? etlB : etlA;
                    TryDelete(current);
                    StartCapture(current);                      // resume at once  — gap closes
                    Interlocked.Increment(ref _filesProcessed);

                    // Processing happens only after capture has resumed, so it does not extend
                    // the gap.
                    await ProcessFileAsync(processor, closed, pcap, ct);
                    TryDelete(closed);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _lastError = ex.Message;
                    _logger.LogWarning(ex, "Packet capture cycle failed; continuing.");
                }
            }
        }
        finally
        {
            SafeRun("stop", "stop");
            SafeRun("filter remove", "filter remove");

            // Process whatever the final capture window holds, then surface any partial exchanges.
            try
            {
                await ProcessFileAsync(processor, current, pcap, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Final capture process failed (ignored).");
            }

            AppendAll(processor.Flush());
            TryDelete(etlA);
            TryDelete(etlB);
            TryDelete(pcap);
        }
    }

    private void StartCapture(string etl) => RunPktmon(
        $"start -c --pkt-size 0 --comp all --file-name \"{etl}\" --file-size {_options.PacketFileSizeMb}");

    private async Task ProcessFileAsync(PcapProcessor processor, string etl, string pcap, CancellationToken ct)
    {
        if (!File.Exists(etl))
        {
            return;
        }

        TryDelete(pcap);
        RunPktmon($"etl2pcap \"{etl}\" -o \"{pcap}\"");
        if (!File.Exists(pcap))
        {
            return;
        }

        var bytes = await File.ReadAllBytesAsync(pcap, ct);
        Interlocked.Exchange(ref _packetsSeen, processor.PacketsSeen);
        AppendAll(processor.Process(bytes));
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

        // Drain both pipes concurrently before waiting, so a child that fills its stderr buffer
        // while we block on stdout cannot deadlock.
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        process.WaitForExit(30_000);
        var stderr = stderrTask.GetAwaiter().GetResult();
        _ = stdoutTask.GetAwaiter().GetResult();

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

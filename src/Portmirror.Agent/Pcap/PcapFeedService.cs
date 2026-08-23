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
            if (_options.PacketIntervalSeconds <= 0)
            {
                _logger.LogInformation("Packet feed started (pktmon, batch mode — exchanges surface on stop).");
            }
            else
            {
                _logger.LogInformation("Packet feed started (pktmon, {Interval}s windows).", _options.PacketIntervalSeconds);
            }

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
        var processor = new PcapProcessor(_redactor, _options.PacketServerPorts, LocalIpv4Addresses());
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
        foreach (var command in FilterCommands())
        {
            SafeRun("filter add", command);
        }

        var interval = _options.PacketIntervalSeconds;
        var batch = interval <= 0;

        TryDelete(etlA);
        var current = etlA;
        StartCapture(current);

        try
        {
            // Batch mode: one continuous capture with no interval boundaries, so nothing in
            // flight is ever cut. It surfaces only once the feed stops (the finally below), since
            // pktmon cannot convert a still-running capture.
            if (batch)
            {
                await DelayUntilCancelled(ct);
            }

            while (!batch && !ct.IsCancellationRequested)
            {
                await DelayQuietly(TimeSpan.FromSeconds(Math.Max(1, interval)), ct);
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

                    // A connection that spanned this window's stop/start lost the bytes in flight;
                    // release whatever came after the hole so it is not stranded on that flow
                    // until the connection finally closes.
                    AppendAll(processor.RecoverStalled());
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
        var produced = processor.Process(bytes);
        Interlocked.Exchange(ref _packetsSeen, processor.PacketsSeen);
        AppendAll(produced);
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

    private IReadOnlyList<string> FilterCommands() => BuildFilterCommands(_options.PacketServerPorts);

    /// <summary>
    /// The pktmon <c>filter add</c> commands for the configured server ports — one per port, which
    /// pktmon ORs together. Pure so it can be tested without a running capture.
    /// </summary>
    internal static IReadOnlyList<string> BuildFilterCommands(int[]? ports)
    {
        if (ports is null || ports.Length == 0)
        {
            // No hint: capture all TCP. Broad, but on a busy host the volume can overrun pktmon
            // (dropped packets) — name the server ports to scope it tightly.
            return new[] { "filter add portmirror -t TCP" };
        }

        // One filter per port, on the port ALONE. Combining a transport type with a port in one
        // pktmon filter (`-t TCP -p <port>`) captures almost nothing — measured on Server 2022 —
        // whereas the port on its own captures the whole conversation. Scoping to just the ports of
        // interest keeps the capture small, which is what avoids the drops that scale with volume:
        // a busy all-TCP capture overruns pktmon's buffer and loses the very traffic being chased.
        var commands = new List<string>();
        var seen = new HashSet<int>();
        foreach (var port in ports)
        {
            if (port > 0 && seen.Add(port))
            {
                commands.Add($"filter add portmirror{port} -p {port}");
            }
        }

        return commands.Count > 0 ? commands : new[] { "filter add portmirror -t TCP" };
    }

    /// <summary>
    /// The host's own IPv4 addresses, used to tell an outbound call (this host is the client) from
    /// an inbound one (this host is the server).
    /// </summary>
    private static IReadOnlyCollection<string> LocalIpv4Addresses()
    {
        var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var addr in nic.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        ips.Add(addr.Address.ToString());
                    }
                }
            }
        }
        catch
        {
            // If enumeration fails, direction stays Unknown rather than misreported.
        }

        return ips;
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

    private static async Task DelayUntilCancelled(CancellationToken ct)
    {
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
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

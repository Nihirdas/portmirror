using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Portmirror.Agent.Capture;

namespace Portmirror.IisModule;

/// <summary>
/// Ships captured exchanges to the agent off the request thread. Requests enqueue and return
/// immediately; a background loop batches and POSTs. If the agent is unreachable the batch is
/// dropped — capturing traffic must never slow or break the application being observed.
/// </summary>
public sealed class ExchangeSender : IDisposable
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(5) };

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private const int MaxQueued = 2000;
    private const int MaxBatch = 100;

    private readonly ConcurrentQueue<Exchange> _queue = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly Func<ModuleControl> _control;
    private int _dropped;

    public ExchangeSender(Func<ModuleControl> control)
    {
        _control = control;
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public int Dropped => Volatile.Read(ref _dropped);

    public void Enqueue(Exchange exchange)
    {
        if (_queue.Count >= MaxQueued)
        {
            // Backpressure: drop rather than grow without bound if the agent is down.
            Interlocked.Increment(ref _dropped);
            return;
        }

        _queue.Enqueue(exchange);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var batch = Drain();
                if (batch.Count > 0)
                {
                    await PostAsync(batch, ct);
                }

                await Task.Delay(500, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Swallow: the sender is best-effort and must not throw into the app.
            }
        }
    }

    private List<Exchange> Drain()
    {
        var batch = new List<Exchange>();
        while (batch.Count < MaxBatch && _queue.TryDequeue(out var e))
        {
            batch.Add(e);
        }

        return batch;
    }

    private async Task PostAsync(List<Exchange> batch, CancellationToken ct)
    {
        var control = _control();
        var url = control.AgentUrl.TrimEnd('/') + "/api/ingest";

        try
        {
            var json = JsonSerializer.Serialize(batch, Json);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };

            if (!string.IsNullOrEmpty(control.AuthToken))
            {
                request.Headers.TryAddWithoutValidation("X-Portmirror-Token", control.AuthToken);
            }

            using var response = await Http.SendAsync(request, ct);
            // Response ignored; if the agent rejects a batch there is nothing useful to do here.
        }
        catch
        {
            // Agent down or unreachable: drop this batch. Never surface to the request.
        }
    }

    public void Dispose()
    {
        try
        {
            _cts.Cancel();
            _loop.Wait(TimeSpan.FromSeconds(3));
        }
        catch
        {
            // Shutting down; ignore.
        }

        _cts.Dispose();
    }
}

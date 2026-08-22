using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Portmirror.Agent.Capture;
using Portmirror.Agent.Http;
using Portmirror.Agent.Redaction;

namespace Portmirror.IisModule;

/// <summary>
/// Takes raw captures off the request thread and does everything expensive here on a background
/// loop: decompression, redaction, mapping, and the network POST. The request thread only ever
/// enqueues a byte copy, so nothing the module does adds latency to the hosted application.
/// If the agent is unreachable, batches are dropped.
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

    private readonly ConcurrentQueue<RawExchange> _queue = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly Func<ModuleControl> _control;
    private readonly Redactor _redactor;
    private int _dropped;

    public ExchangeSender(Func<ModuleControl> control, Redactor redactor)
    {
        _control = control;
        _redactor = redactor;
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public int Dropped => Volatile.Read(ref _dropped);

    public void Enqueue(RawExchange raw)
    {
        if (_queue.Count >= MaxQueued)
        {
            Interlocked.Increment(ref _dropped);
            return;
        }

        _queue.Enqueue(raw);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var batch = DrainAndTransform();
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
                // Best-effort; never throw out of the loop.
            }
        }
    }

    private List<Exchange> DrainAndTransform()
    {
        var batch = new List<Exchange>();
        while (batch.Count < MaxBatch && _queue.TryDequeue(out var raw))
        {
            try
            {
                batch.Add(Transform(raw));
            }
            catch
            {
                // A single malformed capture must not sink the batch.
            }
        }

        return batch;
    }

    /// <summary>
    /// Turns a raw capture into a redacted exchange — the CPU-heavy work (inflate, regex redaction,
    /// mapping), all here on the background thread rather than the request thread.
    /// </summary>
    private Exchange Transform(RawExchange raw)
    {
        var request = BuildMessage(MessageKind.Request, raw.RequestHeaders, raw.RequestBody, raw.RequestTruncated);
        var response = BuildMessage(MessageKind.Response, raw.ResponseHeaders, raw.ResponseBody, raw.ResponseTruncated);

        return new Exchange
        {
            CorrelationId = Guid.NewGuid().ToString("n"),
            Tier = CaptureTier.IisModule,
            Direction = CaptureDirection.Inbound,   // the module observes requests served by this app
            StartedUtc = raw.StartedUtc,
            CompletedUtc = raw.CompletedUtc,
            DurationMs = Math.Round((raw.CompletedUtc - raw.StartedUtc).TotalMilliseconds, 3),
            Verb = raw.Verb,
            Url = _redactor.RedactUrl(raw.RawUrl),
            StatusCode = raw.StatusCode,
            ClientIp = raw.ClientIp,
            Request = request,
            Response = response
        };
    }

    private HttpMessage BuildMessage(
        MessageKind kind, List<KeyValuePair<string, string>> headers, byte[] body, bool truncated)
    {
        var parsed = new ParsedMessage { Kind = kind, Headers = headers, Body = body, BodyTruncated = truncated };
        BodyDecoder.Decode(parsed);
        return MessageMapper.ToHttpMessage(parsed, _redactor);
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
        }
        catch
        {
            // Agent down / unreachable: drop the batch. Never surface to the app.
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
        }

        _cts.Dispose();
    }
}

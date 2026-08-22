using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Web;
using Portmirror.Agent.Faults;
using Portmirror.Agent.Redaction;

namespace Portmirror.IisModule;

/// <summary>
/// The in-process capture tier: a server-level IIS module that observes every inbound request to
/// the app pools it is installed in — including same-host traffic packet capture cannot see — reads
/// request and response bodies, and can inject fault responses. Installing it costs one recycle;
/// after that capture and faults toggle at runtime through the control file with no recycle.
///
/// Its overriding rule is to never affect the hosted application. On the request thread it only
/// copies bytes and enqueues; all expensive work (decompression, redaction, mapping, the POST to
/// the agent) happens on the sender's background thread. It is dormant until the control file
/// enables it, and every operation is wrapped so a failure can never surface into the pipeline.
/// </summary>
public sealed class PortmirrorHttpModule : IHttpModule
{
    private const string ItemFilter = "portmirror.filter";
    private const string ItemStart = "portmirror.start";
    private const string ItemSkip = "portmirror.skip";

    private static readonly ControlLoader Control = new();
    private static readonly Redactor SharedRedactor = new(enabled: true);
    private static readonly Lazy<ExchangeSender> Sender =
        new(() => new ExchangeSender(Control.Current, SharedRedactor));

    // Delay faults hold a request thread for their duration (that is the point — simulating a slow
    // dependency), so the cap is deliberately modest. Point a delay rule at a specific endpoint on
    // a test box, never a hot production path.
    private const int MaxDelayMs = 10_000;

    public void Init(HttpApplication context)
    {
        context.BeginRequest += OnBeginRequest;
        context.EndRequest += OnEndRequest;
    }

    private void OnBeginRequest(object sender, EventArgs e)
    {
        try
        {
            var app = (HttpApplication)sender;
            var ctx = app.Context;
            var control = Control.Current();

            if (control.HasFaults && TryInjectFault(app, ctx, control))
            {
                return;
            }

            if (!control.CaptureEnabled)
            {
                return;
            }

            // Cheap on the request thread: record the start and install the response filter.
            ctx.Items[ItemStart] = DateTimeOffset.UtcNow;
            var filter = new ResponseCaptureStream(ctx.Response.Filter, control.MaxBodyBytes);
            ctx.Response.Filter = filter;
            ctx.Items[ItemFilter] = filter;
        }
        catch
        {
            // Never let capture affect the request.
        }
    }

    private void OnEndRequest(object sender, EventArgs e)
    {
        try
        {
            var ctx = ((HttpApplication)sender).Context;
            if (ctx.Items[ItemSkip] is true || ctx.Items[ItemStart] is not DateTimeOffset started)
            {
                return;
            }

            var control = Control.Current();
            var request = ctx.Request;
            var response = ctx.Response;
            var filter = ctx.Items[ItemFilter] as ResponseCaptureStream;

            // By EndRequest the body is fully received, so this read does not block; and the
            // handler has finished, so touching InputStream cannot disturb it.
            var (reqBody, reqTruncated) = ReadRequestBody(request, control.MaxBodyBytes);

            var raw = new RawExchange
            {
                StartedUtc = started,
                CompletedUtc = DateTimeOffset.UtcNow,
                Verb = request.HttpMethod,
                RawUrl = SafeRawUrl(request),
                StatusCode = response.StatusCode,
                ClientIp = request.UserHostAddress,
                RequestHeaders = ToHeaderList(request.Headers),
                RequestBody = reqBody,
                RequestTruncated = reqTruncated,
                ResponseHeaders = ToHeaderList(response.Headers),
                ResponseBody = filter?.GetCapturedBytes() ?? Array.Empty<byte>(),
                ResponseTruncated = filter?.Truncated ?? false
            };

            // Redaction, decompression and mapping all happen on the sender's thread, not here.
            Sender.Value.Enqueue(raw);
        }
        catch
        {
        }
    }

    private static bool TryInjectFault(HttpApplication app, HttpContext ctx, ModuleControl control)
    {
        var decision = FaultMatcher.Match(control.Faults, ctx.Request.HttpMethod, SafeRawUrl(ctx.Request));
        if (decision is null)
        {
            return false;
        }

        if (decision.DelayMs > 0)
        {
            Thread.Sleep(Math.Min(decision.DelayMs, MaxDelayMs));
        }

        if (decision.DelayOnly)
        {
            return false;   // delay applied; let the request run normally
        }

        var response = ctx.Response;
        response.Clear();
        response.StatusCode = decision.Status;
        // Otherwise IIS replaces a 4xx/5xx body with its own generic error page.
        response.TrySkipIisCustomErrors = true;
        response.ContentType = string.IsNullOrEmpty(decision.ContentType) ? "text/plain" : decision.ContentType;
        if (!string.IsNullOrEmpty(decision.Body))
        {
            response.Write(decision.Body);
        }

        ctx.Items[ItemSkip] = true;
        app.CompleteRequest();
        return true;
    }

    private static (byte[] Body, bool Truncated) ReadRequestBody(HttpRequest request, int maxBytes)
    {
        try
        {
            var input = request.InputStream;   // buffered and fully received at EndRequest
            if (input is null || input.Length == 0)
            {
                return (Array.Empty<byte>(), false);
            }

            var restore = input.CanSeek ? input.Position : 0L;
            if (input.CanSeek)
            {
                input.Position = 0;
            }

            using var ms = new MemoryStream();
            var buffer = new byte[16 * 1024];
            var truncated = false;
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                var room = maxBytes - (int)ms.Length;
                if (room <= 0)
                {
                    truncated = true;
                    break;
                }

                ms.Write(buffer, 0, Math.Min(room, read));
                if (room < read)
                {
                    truncated = true;
                    break;
                }
            }

            if (input.CanSeek)
            {
                input.Position = restore;
            }

            return (ms.ToArray(), truncated);
        }
        catch
        {
            return (Array.Empty<byte>(), false);
        }
    }

    private static List<KeyValuePair<string, string>> ToHeaderList(System.Collections.Specialized.NameValueCollection headers)
    {
        var list = new List<KeyValuePair<string, string>>(headers.Count);
        foreach (string? name in headers)
        {
            if (name is null)
            {
                continue;
            }

            list.Add(new KeyValuePair<string, string>(name, headers[name] ?? string.Empty));
        }

        return list;
    }

    private static string SafeRawUrl(HttpRequest request)
    {
        try
        {
            return request.RawUrl ?? request.Url?.PathAndQuery ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    public void Dispose()
    {
    }
}

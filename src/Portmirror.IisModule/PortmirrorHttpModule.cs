using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Web;
using Portmirror.Agent.Capture;
using Portmirror.Agent.Faults;
using Portmirror.Agent.Http;
using Portmirror.Agent.Redaction;

namespace Portmirror.IisModule;

/// <summary>
/// The in-process capture tier. Registered as a server-level IIS module, it observes every
/// inbound request to the app pools it is installed in — including same-host traffic that packet
/// capture cannot see — reads request and response bodies without disturbing the application, and
/// can inject fault responses. Installing it costs one recycle; after that capture and faults
/// toggle at runtime through the control file, with no recycle.
///
/// It is dormant until the control file enables it, and everything it does is best-effort: any
/// failure is swallowed so the hosted application is never affected.
/// </summary>
public sealed class PortmirrorHttpModule : IHttpModule
{
    private const string ItemFilter = "portmirror.filter";
    private const string ItemReqBody = "portmirror.reqbody";
    private const string ItemReqTruncated = "portmirror.reqtrunc";
    private const string ItemStart = "portmirror.start";
    private const string ItemSkip = "portmirror.skip";

    // Shared across every module instance in the worker process.
    private static readonly ControlLoader Control = new();
    private static readonly Lazy<ExchangeSender> Sender = new(() => new ExchangeSender(Control.Current));
    private static readonly Redactor SharedRedactor = new(enabled: true);

    private const int MaxDelayMs = 60_000;

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
                return;   // request short-circuited with an injected response
            }

            if (!control.CaptureEnabled)
            {
                return;   // dormant
            }

            ctx.Items[ItemStart] = DateTimeOffset.UtcNow;
            CaptureRequestBody(ctx, control.MaxBodyBytes);

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

            var request = ctx.Request;
            var response = ctx.Response;

            var reqBody = ctx.Items[ItemReqBody] as byte[] ?? Array.Empty<byte>();
            var reqTruncated = ctx.Items[ItemReqTruncated] is true;
            var filter = ctx.Items[ItemFilter] as ResponseCaptureStream;
            var respBody = filter?.GetCapturedBytes() ?? Array.Empty<byte>();

            var reqMsg = BuildMessage(MessageKind.Request, ToHeaderList(request.Headers), reqBody, reqTruncated);
            var respMsg = BuildMessage(MessageKind.Response, ToHeaderList(response.Headers), respBody,
                filter?.Truncated ?? false);

            var completed = DateTimeOffset.UtcNow;
            var exchange = new Exchange
            {
                CorrelationId = Guid.NewGuid().ToString("n"),
                Tier = CaptureTier.IisModule,
                StartedUtc = started,
                CompletedUtc = completed,
                DurationMs = Math.Round((completed - started).TotalMilliseconds, 3),
                Verb = request.HttpMethod,
                Url = SharedRedactor.RedactUrl(SafeRawUrl(request)),
                StatusCode = response.StatusCode,
                ClientIp = request.UserHostAddress,
                Request = reqMsg,
                Response = respMsg
            };

            Sender.Value.Enqueue(exchange);
        }
        catch
        {
            // Best-effort; drop on any error.
        }
    }

    /// <summary>Injects a fault response when a rule matches. Returns true if the request was short-circuited.</summary>
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
        response.ContentType = string.IsNullOrEmpty(decision.ContentType) ? "text/plain" : decision.ContentType;
        if (!string.IsNullOrEmpty(decision.Body))
        {
            response.Write(decision.Body);
        }

        ctx.Items[ItemSkip] = true;   // do not also capture this synthetic response
        app.CompleteRequest();
        return true;
    }

    private static void CaptureRequestBody(HttpContext ctx, int maxBytes)
    {
        try
        {
            // GetBufferedInputStream reads a copy while leaving the real body intact for the
            // handler — essential for SOAP/WCF endpoints, which break if the input is consumed.
            var stream = ctx.Request.GetBufferedInputStream();
            if (stream is null)
            {
                return;
            }

            using var ms = new MemoryStream();
            var buffer = new byte[16 * 1024];
            var truncated = false;
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
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

            ctx.Items[ItemReqBody] = ms.ToArray();
            ctx.Items[ItemReqTruncated] = truncated;
        }
        catch
        {
            // If the body cannot be buffered, capture proceeds without it.
        }
    }

    private static HttpMessage BuildMessage(
        MessageKind kind, List<KeyValuePair<string, string>> headers, byte[] body, bool truncated)
    {
        var parsed = new ParsedMessage { Kind = kind, Headers = headers, Body = body, BodyTruncated = truncated };
        BodyDecoder.Decode(parsed);   // undo Content-Encoding if present, exactly as the packet feed does
        return MessageMapper.ToHttpMessage(parsed, SharedRedactor);
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
        // The shared sender is process-lived; nothing per-instance to release.
    }
}

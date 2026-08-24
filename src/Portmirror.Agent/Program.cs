using Portmirror.Agent;
using Portmirror.Agent.Api;
using Portmirror.Agent.Capture;
using Portmirror.Agent.Redaction;
using Portmirror.Agent.Storage;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables("PORTMIRROR_");

var options = builder.Configuration.GetSection(AgentOptions.SectionName).Get<AgentOptions>()
              ?? new AgentOptions();

builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.SectionName));

// Lets the same binary run as a console app for a quick look and as a Windows service in anger.
builder.Services.AddWindowsService();

builder.Logging.AddSimpleConsole(o =>
{
    o.SingleLine = true;
    o.TimestampFormat = "HH:mm:ss ";
});

// Kestrel binds a socket directly, so no HTTP.SYS URL reservation is needed — and the agent's
// own traffic never shows up in the HTTP.SYS provider it is reading, so it cannot capture itself.
builder.WebHost.UseUrls($"http://0.0.0.0:{options.Port}");

builder.Services.AddSingleton(new ExchangeRing(options.Capacity));
builder.Services.AddSingleton(new Redactor(options.RedactionEnabled));
builder.Services.AddSingleton<EtwCaptureService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<EtwCaptureService>());

// Stops capture when no viewer has polled for a while — the basis of on-demand capture.
builder.Services.AddSingleton<IdleCaptureMonitor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<IdleCaptureMonitor>());

// The packet (body) feed is Windows-only and off unless enabled; register it only there.
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<Portmirror.Agent.Pcap.PcapFeedService>();
}

var app = builder.Build();

app.UsePortmirrorAuth();
app.MapPortmirror();

// Auto-start the packet feed only when capture auto-starts. On-demand deployments
// (AutoStartCapture=false) leave it idle until a viewer starts capture via the API.
if (OperatingSystem.IsWindows() && options.PacketCaptureEnabled && options.AutoStartCapture)
{
    var feed = app.Services.GetRequiredService<Portmirror.Agent.Pcap.PcapFeedService>();
    var problem = feed.TryStart();
    if (problem is not null)
    {
        app.Logger.LogWarning("Packet feed not started: {Reason}", problem);
    }
}

app.Logger.LogInformation(
    "portmirror listening on http://0.0.0.0:{Port} (retaining {Capacity} exchanges, redaction {Redaction})",
    options.Port,
    options.Capacity,
    options.RedactionEnabled ? "on" : "OFF");

app.Run();

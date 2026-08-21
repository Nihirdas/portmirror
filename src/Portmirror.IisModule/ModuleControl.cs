using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Portmirror.Agent.Faults;

namespace Portmirror.IisModule;

/// <summary>
/// The module's runtime configuration, read from a control file on disk. Everything about the
/// module is driven from here — whether it captures at all, where to send, how much body to keep,
/// and any fault rules — so behaviour changes with no redeploy and no app-pool recycle.
/// </summary>
public sealed class ModuleControl
{
    /// <summary>Master switch. Off by default: an installed module is dormant until enabled.</summary>
    public bool CaptureEnabled { get; set; }

    /// <summary>Where to POST captured exchanges.</summary>
    public string AgentUrl { get; set; } = "http://localhost:9099";

    /// <summary>Optional shared token, sent as X-Portmirror-Token to match the agent's auth.</summary>
    public string? AuthToken { get; set; }

    /// <summary>Cap on captured request/response body bytes, each.</summary>
    public int MaxBodyBytes { get; set; } = 256 * 1024;

    /// <summary>Fault-injection rules, evaluated in order. Empty = pass everything through.</summary>
    public List<FaultRule> Faults { get; set; } = new();

    [JsonIgnore]
    public bool HasFaults => Faults is { Count: > 0 };
}

/// <summary>
/// Loads <see cref="ModuleControl"/> from the control file and re-reads it only when the file
/// changes, so polling on every request is cheap. Never throws: a missing or malformed file
/// yields a dormant, safe default rather than disturbing the hosted application.
/// </summary>
public sealed class ControlLoader
{
    // %ProgramData%\Portmirror\module.json — writable by an admin / the agent, no recycle needed.
    public static readonly string DefaultPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Portmirror", "module.json");

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    private readonly string _path;
    private readonly object _gate = new();
    private ModuleControl _current = new();
    private DateTime _lastWriteUtc = DateTime.MinValue;
    private long _lastLength = -1;
    private DateTime _lastCheckUtc = DateTime.MinValue;

    public ControlLoader(string? path = null) => _path = path ?? DefaultPath;

    /// <summary>Returns the current control, re-reading the file at most every couple of seconds.</summary>
    public ModuleControl Current()
    {
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            if ((now - _lastCheckUtc).TotalSeconds < 2)
            {
                return _current;
            }

            _lastCheckUtc = now;

            try
            {
                var info = new FileInfo(_path);
                if (!info.Exists)
                {
                    _current = new ModuleControl();
                    _lastWriteUtc = DateTime.MinValue;
                    _lastLength = -1;
                    return _current;
                }

                // Only re-parse when the file actually changed.
                if (info.LastWriteTimeUtc == _lastWriteUtc && info.Length == _lastLength)
                {
                    return _current;
                }

                var text = File.ReadAllText(_path);
                var parsed = JsonSerializer.Deserialize<ModuleControl>(text, Json);
                if (parsed is not null)
                {
                    _current = parsed;
                    _lastWriteUtc = info.LastWriteTimeUtc;
                    _lastLength = info.Length;
                }
            }
            catch
            {
                // Keep the last good control; never let a bad file take down the app.
            }

            return _current;
        }
    }
}

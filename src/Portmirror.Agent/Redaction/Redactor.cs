using System.Text;
using System.Text.RegularExpressions;

namespace Portmirror.Agent.Redaction;

/// <summary>
/// Masks secrets before an exchange ever leaves the agent. On by default and meant to stay
/// that way: a traffic recorder on an application server sees card numbers, CVVs and bearer
/// tokens, and none of that should reach a dashboard, a log file or a bug report.
/// </summary>
public sealed class Redactor
{
    public const string Mask = "***REDACTED***";

    private static readonly TimeSpan Budget = TimeSpan.FromMilliseconds(250);

    /// <summary>Header names whose value is replaced wholesale.</summary>
    private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-access-token",
        "authentication"
    };

    /// <summary>Query-string parameters whose value is a secret; the value is masked, the name kept.</summary>
    private static readonly Regex SensitiveQueryParam = new(
        @"([?&](?:password|passwd|pwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|apikey|auth|authorization|sig|signature|cvv|pin|session|sessionid)=)[^&#\s]*",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, Budget);

    /// <summary>Candidate primary account numbers: 13-19 digits, verified with Luhn before masking.</summary>
    private static readonly Regex CardCandidate = new(
        @"\b\d{13,19}\b", RegexOptions.Compiled, Budget);

    /// <summary>JSON string values behind a sensitive key.</summary>
    private static readonly Regex JsonSensitive = new(
        @"(""(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_?key|cvv|cvc|cav|cav2|cvv2|pin|authorization)""\s*:\s*)""[^""]*""",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, Budget);

    /// <summary>XML element text behind a sensitive element name.</summary>
    private static readonly Regex XmlSensitive = new(
        @"(<([A-Za-z0-9_.:-]*(?:password|passwd|pwd|secret|token|api_?key|cvv|cvc|cav|pin|authorization))\b[^>]*>)([^<]*)(</\2>)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, Budget);

    public Redactor(bool enabled = true) => Enabled = enabled;

    public bool Enabled { get; }

    /// <summary>Masks a request or response body. Returns the input unchanged when disabled.</summary>
    public string? RedactBody(string? body)
    {
        if (!Enabled || string.IsNullOrEmpty(body))
        {
            return body;
        }

        try
        {
            var result = JsonSensitive.Replace(body, m => m.Groups[1].Value + "\"" + Mask + "\"");
            result = XmlSensitive.Replace(result, m => m.Groups[1].Value + Mask + m.Groups[4].Value);
            return MaskCardNumbers(result);
        }
        catch (RegexMatchTimeoutException)
        {
            // Never let a pathological payload stall capture, and never emit it unmasked.
            return Mask;
        }
    }

    /// <summary>Returns a copy of the headers with sensitive values masked.</summary>
    public Dictionary<string, string> RedactHeaders(IEnumerable<KeyValuePair<string, string>> headers)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in headers)
        {
            // KeyValuePair deconstruction is unavailable on net48, where this file is also
            // compiled into the IIS module; use the members directly.
            result[header.Key] = Enabled && SensitiveHeaders.Contains(header.Key) ? Mask : header.Value;
        }

        return result;
    }

    /// <summary>Masks card numbers appearing in a query string.</summary>
    public string? RedactUrl(string? url)
    {
        if (!Enabled || string.IsNullOrEmpty(url))
        {
            return url;
        }

        try
        {
            var masked = SensitiveQueryParam.Replace(url, m => m.Groups[1].Value + Mask);
            return MaskCardNumbers(masked);
        }
        catch (RegexMatchTimeoutException)
        {
            // Never emit an unredacted URL; a pathological input is masked wholesale.
            return Mask;
        }
    }

    private static string MaskCardNumbers(string input) =>
        CardCandidate.Replace(input, static m =>
        {
            var digits = m.Value;
            return PassesLuhn(digits) ? MaskAllButLast4(digits) : digits;
        });

    private static string MaskAllButLast4(string digits)
    {
        if (digits.Length <= 4)
        {
            return new string('*', digits.Length);
        }

        var sb = new StringBuilder(digits.Length);
        sb.Append('*', digits.Length - 4);
        sb.Append(digits, digits.Length - 4, 4);
        return sb.ToString();
    }

    /// <summary>
    /// Luhn check digit. Used to keep long numeric identifiers — order numbers, timestamps,
    /// correlation ids — from being mangled as if they were card numbers.
    /// </summary>
    internal static bool PassesLuhn(string digits)
    {
        if (string.IsNullOrEmpty(digits))
        {
            return false;
        }

        var sum = 0;
        var alternate = false;

        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var c = digits[i];
            if (c < '0' || c > '9')
            {
                return false;
            }

            var value = c - '0';

            if (alternate)
            {
                value *= 2;
                if (value > 9)
                {
                    value -= 9;
                }
            }

            sum += value;
            alternate = !alternate;
        }

        return sum % 10 == 0;
    }
}

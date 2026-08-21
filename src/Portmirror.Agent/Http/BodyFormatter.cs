using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml;

namespace Portmirror.Agent.Http;

public enum BodyFormat
{
    Empty,
    Json,
    Xml,
    Text,
    Binary
}

/// <summary>
/// Decides what a body is, and renders JSON and XML readably. Every method here is safe on
/// malformed input: a body that claims to be JSON but is not comes back unchanged rather than
/// throwing, because a capture tool must show whatever actually arrived.
/// </summary>
public static class BodyFormatter
{
    /// <summary>
    /// Classifies a body. The declared Content-Type is a hint, not the last word — servers
    /// mislabel constantly — so the body's own first non-space character gets the final say
    /// between JSON and XML.
    /// </summary>
    public static BodyFormat Detect(string? contentType, string? body)
    {
        if (string.IsNullOrEmpty(body))
        {
            return BodyFormat.Empty;
        }

        var trimmed = body.AsSpan().TrimStart();
        if (trimmed.Length == 0)
        {
            return BodyFormat.Text;
        }

        var first = trimmed[0];
        var ct = contentType?.ToLowerInvariant() ?? string.Empty;

        // The shape of the payload is more reliable than the label on it.
        if (first is '{' or '[')
        {
            return BodyFormat.Json;
        }

        if (first == '<')
        {
            // Well-formed XML only; HTML is left as text because it rarely parses as XML.
            return ct.Contains("html") ? BodyFormat.Text : BodyFormat.Xml;
        }

        if (ct.Contains("json"))
        {
            return BodyFormat.Json;
        }

        if (ct.Contains("xml"))
        {
            return BodyFormat.Xml;
        }

        return BodyFormat.Text;
    }

    /// <summary>Pretty-prints JSON and XML; returns the input unchanged for anything else or on error.</summary>
    public static string Pretty(string body, string? contentType)
    {
        if (string.IsNullOrEmpty(body))
        {
            return body;
        }

        try
        {
            return Detect(contentType, body) switch
            {
                BodyFormat.Json => PrettyJson(body),
                BodyFormat.Xml => PrettyXml(body),
                _ => body
            };
        }
        catch
        {
            // Malformed payload: show exactly what arrived rather than an error.
            return body;
        }
    }

    private static readonly JsonSerializerOptions PrettyJsonOptions = new()
    {
        WriteIndented = true,
        // The result is shown in a <pre> that HTML-escapes separately, so relaxed escaping
        // keeps angle brackets and ampersands readable instead of turning them into \u escapes.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static string PrettyJson(string body)
    {
        using var doc = JsonDocument.Parse(body);
        return JsonSerializer.Serialize(doc.RootElement, PrettyJsonOptions);
    }

    private static string PrettyXml(string body)
    {
        var settings = new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            OmitXmlDeclaration = false
        };

        // A captured payload is untrusted. Prohibiting DTDs outright (rather than merely
        // nulling the resolver) makes any DOCTYPE throw, so the XXE class of input is never
        // parsed at all — the body is shown verbatim instead of prettified.
        var readerSettings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        var document = new XmlDocument { XmlResolver = null };
        using (var stringReader = new StringReader(body))
        using (var reader = XmlReader.Create(stringReader, readerSettings))
        {
            document.Load(reader);
        }

        var sb = new StringBuilder();
        using (var writer = XmlWriter.Create(sb, settings))
        {
            document.Save(writer);
        }

        return sb.ToString();
    }
}

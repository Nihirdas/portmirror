using Portmirror.Agent.Capture;
using Portmirror.Agent.Redaction;

namespace Portmirror.Agent.Http;

/// <summary>
/// Turns a parsed HTTP message into the shape the API and UI consume, running everything
/// through the redactor on the way. This is the one point where captured payloads are made
/// safe to store, so redaction happens here and cannot be skipped downstream.
/// </summary>
public static class MessageMapper
{
    public static HttpMessage ToHttpMessage(ParsedMessage parsed, Redactor redactor)
    {
        // Explicit guards rather than ArgumentNullException.ThrowIfNull, which is net6+; this
        // file is also compiled into the net48 IIS module.
        if (parsed is null) throw new ArgumentNullException(nameof(parsed));
        if (redactor is null) throw new ArgumentNullException(nameof(redactor));

        var message = new HttpMessage
        {
            ContentType = parsed.ContentType,
            ContentLength = parsed.ContentLength,
            BodyTruncated = parsed.BodyTruncated,
            BodyByteCount = parsed.Body.Length,
            DecodeError = parsed.DecodeError
        };

        foreach (var header in redactor.RedactHeaders(parsed.Headers))
        {
            message.Headers[header.Key] = header.Value;
        }

        var text = BodyDecoder.AsText(parsed.Body);

        if (parsed.Body.Length == 0)
        {
            message.BodyFormat = nameof(BodyFormat.Empty).ToLowerInvariant();
        }
        else if (text is null)
        {
            // Binary: keep the size, drop the bytes — rendering them as a string is misleading.
            message.BodyFormat = nameof(BodyFormat.Binary).ToLowerInvariant();
        }
        else
        {
            var redacted = redactor.RedactBody(text) ?? text;
            message.Body = redacted;
            message.BodyRedacted = !string.Equals(redacted, text, StringComparison.Ordinal);
            message.BodyFormat = BodyFormatter.Detect(parsed.ContentType, redacted)
                .ToString().ToLowerInvariant();
        }

        return message;
    }
}

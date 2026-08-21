using System.IO.Compression;
using System.Text;

namespace Portmirror.Agent.Http;

/// <summary>
/// Undoes Content-Encoding, and decides whether a body is text worth showing or bytes that
/// would be nonsense on screen.
/// </summary>
public static class BodyDecoder
{
    private const int MaxDecompressedBytes = 8 * 1024 * 1024;

    public static void Decode(ParsedMessage message)
    {
        var encoding = message.Header("Content-Encoding");

        if (string.IsNullOrWhiteSpace(encoding) || message.Body.Length == 0)
        {
            return;
        }

        var name = encoding.Trim().ToLowerInvariant();

        // Only the encodings that actually turn up. "identity" is a no-op by definition.
        if (name is "identity" or "none")
        {
            return;
        }

        try
        {
            var (data, capped) = name switch
            {
                "gzip" or "x-gzip" => Inflate(message.Body, raw: false),
                "deflate" => Inflate(message.Body, raw: true),
                _ => throw new NotSupportedException($"Content-Encoding '{name}'")
            };

            message.Body = data;
            message.BodyDecompressed = true;

            // The decompressed output hit the safety cap, so it is cut short — say so, rather
            // than presenting a partial body as complete.
            if (capped)
            {
                message.BodyTruncated = true;
            }
        }
        catch (Exception ex)
        {
            // Keep the compressed bytes and say why they are unreadable, rather than
            // pretending the body is empty.
            message.DecodeError = ex is NotSupportedException
                ? $"not decoded: {encoding}"
                : $"could not decompress {name}: {ex.GetType().Name}";
        }
    }

    private static (byte[] Data, bool Capped) Inflate(byte[] input, bool raw)
    {
        using var source = new MemoryStream(input, writable: false);
        using Stream decompressor = raw
            ? new DeflateStream(source, CompressionMode.Decompress)
            : new GZipStream(source, CompressionMode.Decompress);
        using var output = new MemoryStream();

        var buffer = new byte[16 * 1024];
        var total = 0;

        while (true)
        {
            var read = decompressor.Read(buffer, 0, buffer.Length);
            if (read <= 0)
            {
                break;
            }

            total += read;

            if (total > MaxDecompressedBytes)
            {
                // Guard against a compression bomb: keep what fits, flag it, and stop.
                output.Write(buffer, 0, read - (total - MaxDecompressedBytes));
                return (output.ToArray(), true);
            }

            output.Write(buffer, 0, read);
        }

        return (output.ToArray(), false);
    }

    /// <summary>
    /// True when the bytes look like text. A NUL byte or a high proportion of control
    /// characters means showing it as a string would be misleading.
    /// </summary>
    public static bool LooksTextual(byte[] body)
    {
        if (body.Length == 0)
        {
            return true;
        }

        var suspicious = 0;
        var limit = Math.Min(body.Length, 2048);

        for (var i = 0; i < limit; i++)
        {
            var b = body[i];

            if (b == 0)
            {
                return false;
            }

            var printable = b >= 0x20 || b is 0x09 or 0x0A or 0x0D;
            if (!printable)
            {
                suspicious++;
            }
        }

        return suspicious * 100 / limit < 5;
    }

    /// <summary>Renders a body as text, or null when it is not text.</summary>
    public static string? AsText(byte[] body)
    {
        if (!LooksTextual(body))
        {
            return null;
        }

        // UTF-8 covers what these services emit; Latin-1 never throws for the rest.
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(body);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(body);
        }
    }
}

using System;
using System.IO;

namespace Portmirror.IisModule;

/// <summary>
/// A response filter that copies bytes as they are written to the client, up to a cap, without
/// altering the stream. Installed as HttpResponse.Filter, it lets the module read the response
/// body the application produced while the real response goes out untouched.
/// </summary>
public sealed class ResponseCaptureStream : Stream
{
    private readonly Stream _inner;
    private readonly MemoryStream _captured = new();
    private readonly int _maxBytes;

    public ResponseCaptureStream(Stream inner, int maxBytes)
    {
        _inner = inner;
        _maxBytes = maxBytes < 0 ? 0 : maxBytes;
    }

    public bool Truncated { get; private set; }

    public byte[] GetCapturedBytes() => _captured.ToArray();

    public override void Write(byte[] buffer, int offset, int count)
    {
        // Always pass the real bytes through unchanged.
        _inner.Write(buffer, offset, count);

        var room = _maxBytes - (int)_captured.Length;
        if (room <= 0)
        {
            if (count > 0)
            {
                Truncated = true;
            }

            return;
        }

        var take = Math.Min(room, count);
        _captured.Write(buffer, offset, take);
        if (take < count)
        {
            Truncated = true;
        }
    }

    public override void Flush() => _inner.Flush();
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
    public override void SetLength(long value) => _inner.SetLength(value);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _captured.Dispose();
        }

        base.Dispose(disposing);
    }
}

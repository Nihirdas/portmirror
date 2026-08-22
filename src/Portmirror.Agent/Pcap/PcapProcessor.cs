using Portmirror.Agent.Capture;
using Portmirror.Agent.Redaction;

namespace Portmirror.Agent.Pcap;

/// <summary>
/// The box-independent half of the packet feed: pcapng bytes in, paired HTTP exchanges out.
/// It owns one <see cref="TcpFlowReassembler"/> across successive files, so a connection whose
/// segments span more than one capture interval still reassembles as a single flow. This is pure
/// and deterministic — no pktmon, no clock — so it is fully unit-testable off captured bytes.
/// </summary>
public sealed class PcapProcessor
{
    private readonly TcpFlowReassembler _reassembler;

    public PcapProcessor(Redactor redactor, IEnumerable<int>? serverPorts = null, IEnumerable<string>? localIps = null)
        => _reassembler = new TcpFlowReassembler(redactor, serverPorts, localIps);

    public long PacketsSeen { get; private set; }
    public long SegmentsSeen { get; private set; }
    public int OpenFlows => _reassembler.FlowCount;

    /// <summary>Parses one pcapng file and returns the exchanges it completed.</summary>
    public IReadOnlyList<Exchange> Process(byte[] pcapngBytes)
    {
        ArgumentNullException.ThrowIfNull(pcapngBytes);

        var exchanges = new List<Exchange>();

        foreach (var packet in PcapngReader.Read(pcapngBytes))
        {
            PacketsSeen++;

            var segment = PacketParser.Parse(packet.LinkType, packet.Data, packet.TimestampTicks);
            if (segment is null)
            {
                continue;
            }

            SegmentsSeen++;
            exchanges.AddRange(_reassembler.Accept(segment));
        }

        return exchanges;
    }

    /// <summary>
    /// Releases flows stranded behind a capture gap, surfacing what can be recovered while leaving
    /// the flows open. Call this once after each <see cref="Process"/>: the whole file is in by
    /// then, so any remaining hole is a gap between capture windows that will never be filled.
    /// </summary>
    public IReadOnlyList<Exchange> RecoverStalled() => _reassembler.RecoverStalled();

    /// <summary>Closes every open flow, surfacing any partial exchanges still in flight.</summary>
    public IReadOnlyList<Exchange> Flush() => _reassembler.Flush();
}

namespace Myethos.Network.Codec;

/// <summary>
///     Splitter for the game server on port 5816, whose frames are
///     <code>[u16 size][u16 type][payload: size-4 bytes][footer]</code>
///     where the footer is an 8-byte ASCII token that the size field does <b>not</b> count. A frame
///     therefore occupies exactly <c>size + 8</c> bytes on the wire.
/// </summary>
/// <remarks>
///     The footer is the cheapest framing sanity check the protocol has: it is written by the
///     client's own send path, so a wrong key or a truncated frame shows up as a footer mismatch
///     long before the payload is parsed. It is validated after the frame is fully buffered rather
///     than during the split, because a partial footer cannot be judged.
/// </remarks>
public sealed class FooterPacketSplitter : IPacketSplitter
{
	/// <summary>Footer emitted by the stock 6609 client.</summary>
	public const string DefaultFooter = "TQClient";
	/// <summary>
	///     Footer emitted by some client builds. The reference servers hard-code this second literal
	///     alongside the primary one, so it is accepted here rather than being treated as corruption.
	/// </summary>
	public const string AlternateFooter = "WUuTxfpe";

	private readonly byte[][] _acceptedFooters;
	private readonly int _footerSize;
	private readonly int _maxFrameBytes;
	private readonly int _maxFrameSize;

	/// <param name="clientFooter">Footer the client appends, normally <see cref="DefaultFooter" />.</param>
	/// <param name="acceptAlternateFooter">Also accept <see cref="AlternateFooter" />.</param>
	/// <param name="maxFrameSize">Hard ceiling on the declared payload size.</param>
	public FooterPacketSplitter(string clientFooter = DefaultFooter, bool acceptAlternateFooter = false, int maxFrameSize = 16384)
	{
		ArgumentException.ThrowIfNullOrEmpty(clientFooter);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFrameSize);

		_footerSize = Encoding.ASCII.GetByteCount(clientFooter);
		_maxFrameSize = maxFrameSize;
		_maxFrameBytes = maxFrameSize + _footerSize;

		_acceptedFooters = acceptAlternateFooter ? [Encoding.ASCII.GetBytes(clientFooter), Encoding.ASCII.GetBytes(AlternateFooter)] : [Encoding.ASCII.GetBytes(clientFooter)];
	}
	
	public int LengthSize => FrameHeader.LengthSize;
	public int FooterSize => _footerSize;
	public int MinimumReadable => FrameHeader.MinimumReadable;
	public int MaxFrameSize => _maxFrameSize;
	public int MaxFrameBytes => _maxFrameBytes;

	public PacketSplitState Split(ReadOnlySpan<byte> buffered, out int payloadLength, out int consumed)
	{
		payloadLength = 0;
		consumed = 0;

		if (buffered.Length < FrameHeader.MinimumReadable)
		{
			return PacketSplitState.NeedMore;
		}

		PacketSplitState size = FrameSize.Read(buffered, _maxFrameSize, out int declared);

		if (size != PacketSplitState.Complete)
		{
			return size;
		}

		// The footer rides outside the declared size, so the frame is one tail longer than the
		// size field claims. Getting this wrong is what truncates every frame by eight bytes.
		int total = declared + _footerSize;

		if (buffered.Length < total)
		{
			return PacketSplitState.NeedMore;
		}

		payloadLength = declared;
		consumed = total;
		return PacketSplitState.Complete;
	}

	public bool VerifyFooter(ReadOnlySpan<byte> frame, int payloadLength)
	{
		ReadOnlySpan<byte> footer = frame.Slice(payloadLength, _footerSize);

		foreach (byte[] accepted in _acceptedFooters)
		{
			if (footer.SequenceEqual(accepted))
			{
				return true;
			}
		}

		return false;
	}
}
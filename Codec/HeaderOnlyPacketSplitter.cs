namespace Myethos.Network.Codec;

/// <summary>
///     Splitter for the login server on port 9959, which frames as
///     <code>[u16 size][u16 type][payload: size-4 bytes]</code>
///     with no trailing footer. The size still counts itself, so a frame occupies exactly
///     <c>size</c> bytes on the wire.
/// </summary>
/// <remarks>
///     Kept separate from <see cref="FooterPacketSplitter" /> rather than made a flag on it, because
///     the login server's handshake frames are legal at sizes the game server never produces and
///     because the footer-less server must never have a footer appended: the declared size does not
///     cover it, so the client would read the trailing bytes as the header of the next frame.
/// </remarks>
public sealed class HeaderOnlyPacketSplitter : IPacketSplitter
{
	private readonly int _maxFrameSize;

	/// <param name="maxFrameSize">Hard ceiling on the declared payload size.</param>
	public HeaderOnlyPacketSplitter(int maxFrameSize = 16384)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFrameSize);

		_maxFrameSize = maxFrameSize;
	}

	
	public int LengthSize => FrameHeader.LengthSize;

	
	public int FooterSize => 0;

	
	public int MinimumReadable => FrameHeader.MinimumReadable;

	
	public int MaxFrameSize => _maxFrameSize;

	
	public int MaxFrameBytes => _maxFrameSize;

	
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

		if (buffered.Length < declared)
		{
			return PacketSplitState.NeedMore;
		}

		payloadLength = declared;
		consumed = declared;
		return PacketSplitState.Complete;
	}

	public bool VerifyFooter(ReadOnlySpan<byte> frame, int payloadLength) => true;
}
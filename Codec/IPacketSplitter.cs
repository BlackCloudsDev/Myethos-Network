namespace Myethos.Network.Codec;

/// <summary>
///     Cuts length-prefixed frames out of a partially filled receive buffer. One implementation per
///     transport the 6609 client speaks: the game server on 5816 frames carry a trailing ASCII
///     footer, the login server on 9959 carries none.
/// </summary>
/// <remarks>
///     <para><b>Contract.</b> <see cref="Split" /> must be pure with respect to its input: it may be
///     run over the same window twice and must return the same answer. The receive pipeline relies
///     on that to frame a batch twice, once on the producer side and once on the consumer side,
///     instead of allocating an index array per batch.</para>
///     <para><b>Boundary.</b> It receives only decrypted bytes. Framing is a pure function of
///     plaintext, and keeping the cipher out of this layer is what makes a batch re-splittable.</para>
/// </remarks>
public interface IPacketSplitter
{
	/// <summary>Bytes of framing metadata preceding the payload.</summary>
	int LengthSize { get; }

	/// <summary>Bytes of trailing metadata appended after the payload and excluded from the size.</summary>
	int FooterSize { get; }

	/// <summary>Smallest number of buffered bytes that can yield a verdict.</summary>
	int MinimumReadable { get; }

	/// <summary>Hard ceiling on a declared payload size. Anything larger is a protocol violation.</summary>
	int MaxFrameSize { get; }

	/// <summary>Hard ceiling on payload plus footer, i.e. how large the receive buffer may grow.</summary>
	int MaxFrameBytes { get; }

	/// <summary>
	///     Attempts to cut one frame off the front of <paramref name="buffered" />.
	/// </summary>
	/// <param name="buffered">Contiguous window of already-decrypted bytes, oldest first.</param>
	/// <param name="payloadLength">On <see cref="PacketSplitState.Complete" />, the declared payload size.</param>
	/// <param name="consumed">On <see cref="PacketSplitState.Complete" />, payload plus footer.</param>
	PacketSplitState Split(ReadOnlySpan<byte> buffered, out int payloadLength, out int consumed);

	/// <summary>
	///     Validates the trailing footer of a frame already known to be fully buffered. The span must
	///     be the whole frame including the footer, so a footer-less splitter simply returns true.
	/// </summary>
	bool VerifyFooter(ReadOnlySpan<byte> frame, int payloadLength);

	/// <summary>
	///     Throwing convenience wrapper over <see cref="Split" />, for callers that would rather not
	///     branch on the state.
	/// </summary>
	/// <exception cref="InvalidDataException">The buffered bytes cannot be a frame.</exception>
	bool TrySplit(ReadOnlySpan<byte> buffered, out int payloadLength, out int consumed)
	{
		PacketSplitState state = Split(buffered, out payloadLength, out consumed);

		return state switch
		{
			PacketSplitState.Complete => true,
			PacketSplitState.NeedMore => false,
			_ => throw new InvalidDataException($"Packet length {payloadLength} exceeds the negotiated ceiling.")
		};
	}
}
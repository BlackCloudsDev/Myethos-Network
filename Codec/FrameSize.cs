namespace Myethos.Network.Codec;

/// <summary>
///     Shared decode of the little-endian size field, so every splitter rejects the same inputs for
///     the same reasons.
/// </summary>
/// <remarks>
///     Both checks here are protocol violations rather than "need more data", and the distinction
///     matters: <see cref="PacketSplitState.NeedMore" /> makes the receive loop wait, while
///     <see cref="PacketSplitState.Invalid" /> kills the connection. A declared size of zero is the
///     classic symptom of a desynchronised keystream, and letting it be treated as "wait" would
///     wedge the connection instead of dropping it.
/// </remarks>
internal static class FrameSize
{
	/// <summary>
	///     Reads and range-checks the size at the front of <paramref name="buffered" />.
	/// </summary>
	/// <param name="buffered">Decrypted bytes, oldest first.</param>
	/// <param name="maxFrameSize">Hard ceiling on the declared size.</param>
	/// <param name="declared">The decoded size on success.</param>
	/// <returns><see cref="PacketSplitState.Complete" /> when the field itself is sane.</returns>
	public static PacketSplitState Read(ReadOnlySpan<byte> buffered, int maxFrameSize, out int declared)
	{
		declared = FrameHeader.ReadLength(buffered);

		if (declared < FrameHeader.MinimumReadable || declared > maxFrameSize)
		{
			declared = 0;
			return PacketSplitState.Invalid;
		}

		return PacketSplitState.Complete;
	}
}
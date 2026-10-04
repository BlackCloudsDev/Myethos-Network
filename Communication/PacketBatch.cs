namespace Myethos.Network.Communication;

/// <summary>
///     A contiguous run of frames lifted out of a receive buffer, backed by a pooled array.
/// </summary>
/// <remarks>
///     <para>
///         The whole drained region is copied with a single <c>memcpy</c> and the individual frames are
///         then addressed as slices of the same array, so a batch of fifty packets costs one copy and
///         one pool rental instead of fifty of each.
///     </para>
///     <para>
///         Frame boundaries are recovered on the consumer side by re-running the splitter, which is
///         required to be deterministic, so no index array is stored. That is the whole reason
///         <see cref="IPacketSplitter" /> is specified as a pure function of its input: storing fifty
///         offsets would cost more than the copy it saves.
///     </para>
/// </remarks>
internal readonly struct PacketBatch
{
	/// <summary>Pooled backing array.</summary>
	public byte[] Array { get; }

	/// <summary>Valid byte count, equal to the sum of every frame length in the batch.</summary>
	public int Length { get; }

	/// <summary>Number of frames the batch contains.</summary>
	public int Frames { get; }

	/// <summary>Creates a batch view over a pooled array.</summary>
	public PacketBatch(byte[] array, int length, int frames)
	{
		ArgumentNullException.ThrowIfNull(array);
		ArgumentOutOfRangeException.ThrowIfNegative(length);
		ArgumentOutOfRangeException.ThrowIfNegative(frames);

		Array = array;
		Length = length;
		Frames = frames;
	}

	/// <summary>The frames in wire order.</summary>
	public ReadOnlySpan<byte> Span => Array.AsSpan(0, Length);
}
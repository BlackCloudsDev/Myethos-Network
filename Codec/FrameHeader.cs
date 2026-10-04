namespace Myethos.Network.Codec;

/// <summary>
///     The four logical bytes at the front of every Conquer frame:
///     <code>
///     +0  u16  size   little-endian, counts itself, excludes the footer
///     +2  u16  type   little-endian
///     </code>
/// </summary>
/// <remarks>
///     The size field counts <b>itself</b> but <b>not</b> the footer, so a frame occupies
///     <c>size + footerSize</c> bytes on the wire. That asymmetry is the single most common source
///     of framing bugs, so it is stated here once and never re-derived: every reader in this
///     assembly treats <c>consumed = size + footer</c>.
///     <para>
///         The reference servers read the size with <c>BitConverter</c>, which is correct only on a
///         little-endian host. Every read and write here goes through <see cref="BinaryPrimitives" />
///         so the byte order is stated rather than assumed.
///     </para>
/// </remarks>
public static class FrameHeader
{
	/// <summary>Width of the size field.</summary>
	public const int LengthSize = 2;

	/// <summary>Width of the type field.</summary>
	public const int TypeSize = 2;

	/// <summary>Total bytes consumed by the size and type fields.</summary>
	public const int HeaderBytes = LengthSize + TypeSize;

	/// <summary>Offset of the message type relative to the start of the size field.</summary>
	public const int TypeOffset = LengthSize;

	/// <summary>
	///     Smallest number of buffered bytes that can yield a verdict. The size field is two bytes,
	///     but a frame declaring fewer than <see cref="HeaderBytes" /> bytes has no room for a type,
	///     so four bytes is the true minimum. This is the span equivalent of the reference servers'
	///     <c>while (consumed + 2 &lt; examined)</c> guard, tightened to reject junk early.
	/// </summary>
	public const int MinimumReadable = HeaderBytes;

	/// <summary>Reads the little-endian size field.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ushort ReadLength(ReadOnlySpan<byte> source) => BinaryPrimitives.ReadUInt16LittleEndian(source);

	/// <summary>Reads the little-endian type field. The span must be at least <see cref="HeaderBytes" /> long.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ushort ReadType(ReadOnlySpan<byte> source) => BinaryPrimitives.ReadUInt16LittleEndian(source[TypeOffset..]);

	/// <summary>Writes the little-endian size field.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void WriteLength(Span<byte> destination, int payloadLength) => BinaryPrimitives.WriteUInt16LittleEndian(destination, (ushort)payloadLength);

	/// <summary>Writes the little-endian type field.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void WriteType(Span<byte> destination, ushort type) => BinaryPrimitives.WriteUInt16LittleEndian(destination[TypeOffset..], type);
}
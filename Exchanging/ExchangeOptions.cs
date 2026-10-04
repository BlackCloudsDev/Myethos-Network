namespace Myethos.Network.Exchanging;

/// <summary>
///     Configures the pre-game Diffie-Hellman exchange: where the length field sits and which cipher
///     guards traffic until the session installs the negotiated one.
/// </summary>
/// <remarks>
///     The 6609 exchange frame is <b>not</b> framed like a normal packet. Seven junk bytes are
///     prepended, the declared length at offset 7 does <b>not</b> count them, and a footer rides at
///     the end on top of that. The frame therefore totals <c>length + 7</c> bytes, and only the first
///     nine need to be decrypted to learn the length.
/// </remarks>
public sealed record ExchangeOptions
{
	/// <summary>
	///     Byte offset of the length field. The 6609 client uses <c>7</c>.
	/// </summary>
	public int LengthOffset { get; init; } = 7;

	/// <summary>
	///     Creates the pre-exchange cipher for one connection. Must return a fresh instance: the cipher is
	///     stateful, and sharing one across connections would interleave their keystreams.
	/// </summary>
	public Func<INetworkCipher> CipherFactory { get; init; } = static () => new CastCipher();

	/// <summary>
	///     Bytes that must be decrypted before the length field is readable, i.e. everything up to and
	///     including the two length bytes.
	/// </summary>
	public int HeaderSize => LengthOffset + FrameHeader.LengthSize;

	/// <summary>
	///     Ceiling on the declared exchange length. Generous, because the client pads the modulus and
	///     both public keys into one frame, but still a bound: an unchecked value would let a client make
	///     the server grow its receive buffer without limit.
	/// </summary>
	public int MaxExchangeBytes { get; init; } = 1024;

	/// <summary>
	///     Seconds allowed for the whole exchange. The client sends it unprompted immediately after
	///     connecting, so a slow value only widens the window for a socket that will never speak.
	/// </summary>
	public int TimeoutSeconds { get; init; } = 10;

	/// <summary>
	///     Whether to wait for a response frame from the client after the exchange. Off for the 6609
	///     game server, which sends nothing at this point.
	/// </summary>
	public bool AwaitClientConfirmation { get; init; }

	internal void Validate()
	{
		ArgumentOutOfRangeException.ThrowIfNegative(LengthOffset);
		ArgumentNullException.ThrowIfNull(CipherFactory);

		if (HeaderSize > FrameHeader.MinimumReadable)
		{
			throw new ArgumentException($"LengthOffset {LengthOffset} leaves no room for a frame header.",nameof(LengthOffset));
		}

		if (MaxExchangeBytes < FrameHeader.MinimumReadable)
		{
			throw new ArgumentException($"MaxExchangeBytes must be at least {FrameHeader.MinimumReadable}.",nameof(MaxExchangeBytes));
		}

		if (TimeoutSeconds <= 0)
		{
			throw new ArgumentException("TimeoutSeconds must be positive.", nameof(TimeoutSeconds));
		}
	}
}
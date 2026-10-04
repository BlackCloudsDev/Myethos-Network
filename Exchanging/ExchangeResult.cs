namespace Myethos.Network.Exchanging;

/// <summary>Result of handling a Diffie-Hellman exchange frame.</summary>
/// <param name="Success">
///     Whether the exchange completed. A false value terminates the connection without notifying the
///     session again.
/// </param>
/// <param name="Response">
///     Optional bytes to write back before the connection enters its normal receive loop. The 6609 game
///     server sends nothing here; the field exists for the login and cross-server handshakes. The bytes
///     must already carry their own size field and footer, because they are written by the framing path
///     exactly as a normal outbound frame is.
/// </param>
public readonly record struct ExchangeResult(bool Success, ReadOnlyMemory<byte> Response)
{	public static ExchangeResult Ok => new(true, ReadOnlyMemory<byte>.Empty);
	public static ExchangeResult Fail => new(false, ReadOnlyMemory<byte>.Empty);
	public static ExchangeResult Reply(ReadOnlyMemory<byte> response) => new(true, response);
}
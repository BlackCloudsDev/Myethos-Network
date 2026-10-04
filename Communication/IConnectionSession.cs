using Myethos.Network.Exchanging;

namespace Myethos.Network.Communication;

/// <summary>
///     Per-connection behaviour, implemented by the login and game servers.
/// </summary>
/// <remarks>
///     <para><b>Threading contract.</b> This is the part that decides whether a server built on top of
///     this library needs locks, so it is stated precisely:</para>
///     <list type="bullet">
///         <item><description>
///             <see cref="OnConnectedAsync" />, <see cref="OnExchangeAsync" /> and
///             <see cref="OnPacketAsync" /> all run on the connection's assigned dispatch partition, which
///             means they never run concurrently with themselves. A session reads its own connection
///             state without locking.
///         </description></item>
///         <item><description>
///             They can run concurrently with <i>other</i> connections' handlers, so anything shared across
///             players still needs synchronisation.
///         </description></item>
///         <item><description>
///             Handlers for different connections share one worker per partition, so a slow handler delays
///             the other players on its partition by up to <c>MaxFramesPerTurn</c> frames. Keep handlers
///             short and push real work onto your own scheduler.
///         </description></item>
///         <item><description>
///             <see cref="OnDisconnectedAsync" /> runs after the final inbound batch has been processed,
///             so it can safely release everything the connection owns.
///         </description></item>
///     </list>
/// </remarks>
public interface IConnectionSession
{
	/// <summary>
	///     Called once the socket is configured and the connection is registered, before any bytes are
	///     read. This is where a game server sends its handshake request.
	/// </summary>
	ValueTask OnConnectedAsync(ClientConnection connection, CancellationToken cancellationToken);

	/// <summary>
	///     Called with the decrypted exchange frame.
	/// </summary>
	/// <remarks>
	///     The implementation must install the negotiated cipher on <paramref name="connection" /> before
	///     returning, because any bytes the client already sent behind the exchange frame are decrypted
	///     with the new cipher the instant this method returns. A session that answers first and re-keys
	///     second will decrypt that tail with the wrong key and the client will drop.
	/// </remarks>
	ValueTask<ExchangeResult> OnExchangeAsync(
		ClientConnection connection,
		ReadOnlyMemory<byte> frame,
		CancellationToken cancellationToken);

	/// <summary>Called once per decoded frame, in wire order. The span includes the size and type fields.</summary>
	ValueTask OnPacketAsync(
		ClientConnection connection,
		ReadOnlyMemory<byte> packet,
		CancellationToken cancellationToken);

	/// <summary>Called after the final inbound frame has been processed.</summary>
	ValueTask OnDisconnectedAsync(ClientConnection connection);
}
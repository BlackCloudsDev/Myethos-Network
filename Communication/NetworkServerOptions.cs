using Myethos.Network.Exchanging;

namespace Myethos.Network.Communication;

/// <summary>
///     Listener and pipeline tunables. Defaults target the game server on 5816.
/// </summary>
/// <remarks>
///     Every value here has a defensible default for a Conquer 6609 server, so a caller can construct
///     one with <c>new()</c> and get a working configuration. The ones worth understanding before
///     changing them are <see cref="WorkPartitions" />, <see cref="MaxWorkItemsPerTurn" /> and
///     <see cref="ReceiveIdleTimeoutSeconds" />.
/// </remarks>
public sealed record NetworkServerOptions
{
	/// <summary>Interface to bind. <c>null</c>, <c>*</c> and <c>+</c> all mean every interface.</summary>
	public string Host { get; init; } = "0.0.0.0";

	/// <summary>TCP port to bind. 5816 for the game server, 9959 for the login server.</summary>
	public int Port { get; init; } = 5816;

	/// <summary>Pending-connection queue depth handed to <c>listen()</c>.</summary>
	public int Backlog { get; init; } = 512;

	/// <summary>Ceiling on simultaneous connections.</summary>
	public int MaxConnections { get; init; } = 4000;

	/// <summary>Ceiling on simultaneous connections from a single IPv4 address.</summary>
	public int MaxConnectionsPerIp { get; init; } = 16;

	/// <summary>
	///     Connection attempts one address may make per <see cref="AttemptWindowSeconds" /> before it is
	///     banned for <see cref="BanMinutes" />. This is what stops a connect-and-drop loop, which never
	///     trips the live-connection ceiling and still costs a socket, a buffer and a task each round.
	/// </summary>
	public int MaxAttemptsPerIp { get; init; } = 120;

	/// <summary>Length of the connection-rate window.</summary>
	public int AttemptWindowSeconds { get; init; } = 60;

	/// <summary>Cooling-off period applied to an address that exceeded its rate.</summary>
	public int BanMinutes { get; init; } = 2;

	/// <summary>
	///     Initial receive buffer per connection. It grows on demand up to the frame ceiling, so this only
	///     needs to be large enough that a typical read completes a whole frame without waiting for a
	///     second segment.
	/// </summary>
	public int ReceiveBufferSize { get; init; } = 4096;

	/// <summary>Receive buffers created up front in the pool.</summary>
	public int PreallocatedBuffers { get; init; } = 512;

	/// <summary>Socket send/receive buffer hint requested from the operating system.</summary>
	public int SocketBufferSize { get; init; } = 128 * 1024;

	/// <summary>Disable Nagle. Movement packets are small and latency-sensitive.</summary>
	public bool NoDelay { get; init; } = true;

	/// <summary>Keepalive probe interval in seconds. Zero disables keepalive.</summary>
	public int KeepAliveSeconds { get; init; } = 60;

	/// <summary>
	///     Seconds a connection may sit without completing a read before it is dropped. Zero disables the
	///     timeout, which is only correct behind a proxy that reaps dead peers itself.
	/// </summary>
	/// <remarks>
	///     This is the reaper for half-open connections: a client whose cable was cut, or a NAT that
	///     forgot the mapping, never sends a FIN and is indistinguishable from an idle one until the OS
	///     give up hours later. Thirty seconds is comfortably longer than any real client between
	///     packets, including one on a bad mobile link.
	/// </remarks>
	public int ReceiveIdleTimeoutSeconds { get; init; } = 60;

	/// <summary>Seconds allowed for the Diffie-Hellman exchange. Zero falls back to the option's own value.</summary>
	public int ExchangeTimeoutSeconds { get; init; } = 10;

	/// <summary>
	///     Workers per direction, each owning a disjoint set of connections.
	/// </summary>
	/// <remarks>
	///     One worker per partition, so this is also the maximum number of session handlers running at
	///     once. Defaults to the processor count: handlers are mostly short game logic, and oversubscribing
	///     them adds context-switch latency without adding throughput. Each partition gets its own worker in
	///     each direction, so the real ceiling on concurrent work is <c>2 x WorkPartitions</c>.
	/// </remarks>
	public int WorkPartitions { get; init; } = Math.Max(1, Environment.ProcessorCount);

	/// <summary>
	///     Work items one connection may run in a single turn before yielding to the rest of its partition.
	/// </summary>
	/// <remarks>
	///     The knob that decides what a flooding client costs the players sharing its partition. Lower
	///     gives fairer latency and more socket writes; higher gives better batching on the outbound side
	///     and fewer wake-ups on the inbound side. Eight is a good middle for a game server.
	/// </remarks>
	public int MaxWorkItemsPerTurn { get; init; } = 8;

	/// <summary>
	///     Batches buffered per connection before the receive loop suspends.
	/// </summary>
	/// <remarks>
	///     Applying backpressure here, rather than letting the queue grow, is what keeps a slow game-logic
	///     handler from turning into unbounded memory growth. It costs a stalled TCP window, which is the
	///     correct trade: the alternative is an out-of-memory kill that takes every player with it.
	/// </remarks>
	public int InboundQueueCapacity { get; init; } = 32;

	/// <summary>
	///     Frames queued per connection before further sends are refused. An outbound queue is bounded
	///     rather than back-pressured, because a send cannot wait: a client that is not reading is a client
	///     that is gone, and the connection is closed instead of growing memory on its behalf.
	/// </summary>
	public int OutboundQueueCapacity { get; init; } = 2048;

	/// <summary>Upper bound on frames merged into a single socket write.</summary>
	public int MaxSendBatchFrames { get; init; } = 64;

	/// <summary>Upper bound on bytes merged into a single socket write.</summary>
	public int MaxSendBatchBytes { get; init; } = 32 * 1024;

	/// <summary>Accept <c>WUuTxfpe</c> alongside the configured footer. Required by some client builds.</summary>
	public bool AcceptAlternateClientFooter { get; init; }

	/// <summary>Footer appended to every outbound game-server frame. Empty for the login server.</summary>
	public string Footer { get; init; } = "TQServer";

	/// <summary>
	///     The pre-game Diffie-Hellman exchange. Leave null for the login server, which does not run one.
	/// </summary>
	public ExchangeOptions? ExchangeHandshake { get; init; }

	/// <summary>Raised when framing or the exchange fails, before the connection is closed.</summary>
	public Action<ClientConnection, string>? OnProtocolError { get; init; }

	/// <summary>Raised for any exception escaping a session handler or the pipelines.</summary>
	public Action<ClientConnection, Exception>? UnhandledFault { get; init; }

	/// <summary>Raised for every accept the registry refuses.</summary>
	public Action<string, BlockReason>? OnConnectionBlocked { get; init; }

	internal void Validate()
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(Host);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(Port);
		ArgumentOutOfRangeException.ThrowIfLessThan(Backlog, 1);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxConnections);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxConnectionsPerIp);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxAttemptsPerIp);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(AttemptWindowSeconds);
		ArgumentOutOfRangeException.ThrowIfNegative(BanMinutes);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(ReceiveBufferSize);
		ArgumentOutOfRangeException.ThrowIfNegative(PreallocatedBuffers);
		ArgumentOutOfRangeException.ThrowIfNegative(SocketBufferSize);
		ArgumentOutOfRangeException.ThrowIfNegative(ReceiveIdleTimeoutSeconds);
		ArgumentOutOfRangeException.ThrowIfNegative(ExchangeTimeoutSeconds);
		ArgumentOutOfRangeException.ThrowIfNegative(WorkPartitions);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxWorkItemsPerTurn);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(InboundQueueCapacity);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(OutboundQueueCapacity);
		ArgumentOutOfRangeException.ThrowIfLessThan(MaxSendBatchFrames, 1);
		ArgumentOutOfRangeException.ThrowIfLessThan(MaxSendBatchBytes, 1024);

		ExchangeHandshake?.Validate();
	}
}
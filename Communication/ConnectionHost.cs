namespace Myethos.Network.Communication;

/// <summary>
///     State shared by every connection on one listener: the framing rules, the buffer pool, the
///     two work schedulers, and the shutdown signal.
/// </summary>
/// <remarks>
///     Held by reference from each <see cref="ClientConnection" /> rather than copied into it. The
///     receive buffer, the staging buffer and the queues are per connection because they must be; the
///     splitter, the footer bytes and the schedulers are not, and copying them per connection would put
///     four extra references on every client for no benefit.
/// </remarks>
internal sealed class ConnectionHost : IAsyncDisposable
{
	private readonly CancellationTokenSource _shutdown = new();
	private int _disposed;

	public ConnectionHost(NetworkServerOptions options, IPacketSplitter splitter)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(splitter);

		options.Validate();

		Options = options;
		Splitter = splitter;

		// A footer-less splitter must never get a footer appended: the declared size does not cover it, so
		// the client would read the trailing bytes as the header of the next frame.
		Footer = splitter.FooterSize == 0 ? [] : Encoding.ASCII.GetBytes(options.Footer);

		if (Footer.Length != splitter.FooterSize)
		{
			throw new ArgumentException($"Footer \"{options.Footer}\" is {Footer.Length} bytes but the splitter expects {splitter.FooterSize}.",nameof(options));
		}

		Buffers = new BufferPool(options.ReceiveBufferSize, options.PreallocatedBuffers);

		Inbound = new WorkScheduler<PacketBatch>(
			options,
			static connection => connection.Inbound,
			static (connection, batch, token) => connection.ProcessBatchAsync(batch, token),
			static (_, _) => default);

		Outbound = new WorkScheduler<ClientConnection.OutboundFrame>(
			options,
			static connection => connection.Outbound,
			static (connection, frame, token) => connection.StageOutboundAsync(frame, token),
			static (connection, token) => IgnoreOutcome(connection.FlushStagedAsync(token)));
	}

	public NetworkServerOptions Options { get; }

	public IPacketSplitter Splitter { get; }

	/// <summary>Footer bytes appended to every outbound frame; empty for a footer-less listener.</summary>
	public byte[] Footer { get; }

	public BufferPool Buffers { get; }

	/// <summary>Pooled workers that run session handlers.</summary>
	public WorkScheduler<PacketBatch> Inbound { get; }

	/// <summary>Pooled workers that stage and write outbound frames.</summary>
	public WorkScheduler<ClientConnection.OutboundFrame> Outbound { get; }

	/// <summary>Signalled when the listener is shutting down.</summary>
	public CancellationToken Shutdown => _shutdown.Token;

	/// <summary>
	///     Adapts a value-returning operation to the scheduler's discard-the-outcome flush delegate. The
	///     flush reports its own failure by closing the connection, so the scheduler has nothing to do with
	///     the answer.
	/// </summary>
	private static ValueTask IgnoreOutcome(ValueTask<bool> operation) => operation.IsCompletedSuccessfully
		? default
		: AwaitOutcome(operation);

	private static async ValueTask AwaitOutcome(ValueTask<bool> operation)
	{
		await operation.ConfigureAwait(false);
	}

	/// <summary>
	///     Assigns a freshly accepted connection to one partition per direction.
	/// </summary>
	/// <remarks>
	///     Assigning both directions up front keeps the connection's work spread the same way whether it is
	///     sending or receiving, which is what stops a write-heavy player from drifting onto a partition
	///     whose read side is busy.
	/// </remarks>
	public void Attach(ClientConnection connection)
	{
		connection.InboundPartition = Inbound.Assign(connection);
		connection.OutboundPartition = Outbound.Assign(connection);
	}

	/// <summary>Returns a torn-down connection's partitions to the least-populated pool.</summary>
	public void Detach(ClientConnection connection)
	{
		Inbound.Release(connection.InboundPartition);
		Outbound.Release(connection.OutboundPartition);

		connection.InboundPartition = null;
		connection.OutboundPartition = null;
	}

	
	public async ValueTask DisposeAsync()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 1)
		{
			return;
		}

		await _shutdown.CancelAsync().ConfigureAwait(false);

		// The schedulers go last: connections tear down against a still-running worker, and a worker that
		// stopped first would leave queued frames undispatched.
		await Outbound.DisposeAsync().ConfigureAwait(false);
		await Inbound.DisposeAsync().ConfigureAwait(false);

		_shutdown.Dispose();
	}
}
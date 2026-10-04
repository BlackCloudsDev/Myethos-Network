using Serilog;

namespace Myethos.Network.Communication;

/// <summary>
///     TCP listener that accepts Conquer clients and hands each one to a <see cref="ClientConnection" />
///     that owns its own framing, cipher and queues.
/// </summary>
/// <remarks>
///     <para><b>Connection budget.</b> The ceiling is a live-connection limit rather than a rate limit: an
///     accept blocks once it is reached, so the kernel backlog absorbs the excess instead of the server
///     queueing work it has no capacity to run. The per-address registry is checked before a connection is
///     constructed, so a flood costs one rejected socket rather than a buffer, a cipher and two scheduler
///     registrations.</para>
///     <para><b>Ownership.</b> This type owns the host, the host owns the schedulers, and each connection is
///     owned by the task that accepted it. Disposal therefore runs in the only safe order: stop accepting,
///     tear the connections down while the workers are still alive, then stop the workers.</para>
/// </remarks>
public sealed class NetworkServer : IAsyncDisposable
{
	private static readonly ILogger Logger = Log.ForContext(typeof(NetworkServer));

	private readonly ConnectionHost _host;
	private readonly ConnectionRegistry _registry;
	private readonly NetworkServerOptions _options;
	private readonly IConnectionSessionFactory _sessionFactory;
	private readonly SemaphoreSlim _slots;
	private readonly Socket _socket;
	private readonly ConcurrentDictionary<long, ClientConnection> _connections = new();

	private Task? _acceptLoop;
	private long _nextId;
	private int _disposed;
	private int _started;

	/// <param name="splitter">Framing for the transport this server speaks.</param>
	/// <param name="sessionFactory">Creates one session per accepted connection.</param>
	/// <param name="options">Listener and pipeline tunables.</param>
	public NetworkServer(IPacketSplitter splitter, IConnectionSessionFactory sessionFactory, NetworkServerOptions options)
	{
		ArgumentNullException.ThrowIfNull(splitter);
		ArgumentNullException.ThrowIfNull(sessionFactory);
		ArgumentNullException.ThrowIfNull(options);

		_options = options;
		_sessionFactory = sessionFactory;
		_registry = new ConnectionRegistry(
			options.MaxConnectionsPerIp,
			options.MaxAttemptsPerIp,
			options.BanMinutes,
			options.AttemptWindowSeconds);

		// One slot per permitted connection, released as each connection finishes tearing down. This is the
		// accept-side throttle: the loop parks here rather than spinning up work it cannot run.
		_slots = new SemaphoreSlim(options.MaxConnections, options.MaxConnections);
		_host = new ConnectionHost(options, splitter);

		_socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
		SocketTransport.ApplyListenerDefaults(_socket, options);
	}

	/// <summary>Raised after a connection has been accepted and configured.</summary>
	public event Action<ClientConnection>? ConnectionAccepted;

	/// <summary>Raised once a connection has finished tearing down.</summary>
	public event Action<ClientConnection>? ConnectionClosed;

	/// <summary>Number of connections currently live.</summary>
	public int Connected => _connections.Count;

	/// <summary>Addresses currently banned by the rate limiter.</summary>
	public int BannedAddresses => _registry.BannedAddresses;

	/// <summary>Binds, listens, and starts accepting until the token is cancelled.</summary>
	/// <param name="cancellationToken">Stops the accept loop.</param>
	public async Task StartAsync(CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

		if (Interlocked.Exchange(ref _started, 1) == 1)
		{
			throw new InvalidOperationException("The server has already been started.");
		}

		// ReuseAddress lets a restarted listener bind while the previous socket is still in TIME_WAIT, which
		// matters for a server that is restarted more often than connections are closed.
		_socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
		_socket.Bind(new IPEndPoint(IPAddress.Parse(_options.Host), _options.Port));
		_socket.Listen(_options.Backlog);

		Logger.Information(
			"Listening on {Host}:{Port} with {Partitions} partitions per direction, max {MaxConnections} connections.",
			_options.Host,
			_options.Port,
			_options.WorkPartitions,
			_options.MaxConnections);

		using CancellationTokenSource linked =
			CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _host.Shutdown);

		_acceptLoop = Task.Run(() => AcceptLoopAsync(linked.Token), CancellationToken.None);

		await Task.Yield();
	}

	private async Task AcceptLoopAsync(CancellationToken cancellationToken)
	{
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				// Block once the connection budget is spent. Holding the excess in the kernel backlog is the
				// point: the server never allocates for a connection it has no capacity to serve.
				try
				{
					await _slots.WaitAsync(cancellationToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException)
				{
					return;
				}

				Socket accepted;

				try
				{
					accepted = await _socket.AcceptAsync(cancellationToken).ConfigureAwait(false);
				}
				catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
				{
					_slots.Release();
					return;
				}

				IPEndPoint? remote = accepted.RemoteEndPoint as IPEndPoint;

				if (!_registry.TryAcquire(remote, out BlockReason reason))
				{
					SocketTransport.Close(accepted);
					_slots.Release();

					string address = remote?.Address.MapToIPv4().ToString() ?? "unknown";
					_options.OnConnectionBlocked?.Invoke(address, reason);

					Logger.Debug("Refused {Address}: {Reason}.", address, reason);
					continue;
				}

				SocketTransport.ApplyDefaults(accepted, _options);

				ClientConnection connection;
				IConnectionSession session;

				try
				{
					session = _sessionFactory.Create();
					connection = new ClientConnection(
						Interlocked.Increment(ref _nextId),
						remote?.Address.MapToIPv4().ToString() ?? "0.0.0.0",
						accepted,
						_host,
						session);
				}
				catch (Exception ex)
				{
					// A factory that throws must not take the listener down with it.
					SocketTransport.Close(accepted);
					_registry.Release(remote);
					_slots.Release();
					ReportAcceptFault(ex);
					continue;
				}

				connection.Cipher = _options.ExchangeHandshake?.CipherFactory.Invoke() ?? new NetDragonCipher();

				_host.Attach(connection);
				_connections[connection.Id] = connection;

				ConnectionAccepted?.Invoke(connection);

				_ = RunConnectionAsync(connection, remote);
			}
		}
		catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
		{
			// Shutting down.
		}
		catch (Exception ex)
		{
			Logger.Error(ex, "Accept loop stopped unexpectedly.");
		}
		finally
		{
			Logger.Information("Listener stopped accepting connections.");
		}
	}

	private async Task RunConnectionAsync(ClientConnection connection, IPEndPoint? remote)
	{
		try
		{
			await connection.RunAsync().ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_options.UnhandledFault?.Invoke(connection, ex);
		}
		finally
		{
			_connections.TryRemove(connection.Id, out _);
			_registry.Release(remote);
			_slots.Release();

			ConnectionClosed?.Invoke(connection);
		}
	}

	/// <summary>
	///     Reports a failure that happened before a connection object existed, so there is nothing to hand
	///     the fault callback.
	/// </summary>
	private void ReportAcceptFault(Exception ex)
	{
		if (_options.UnhandledFault is { } handler)
		{
			try
			{
				handler(null!, ex);
				return;
			}
			catch (Exception inner)
			{
				ex = inner;
			}
		}

		Logger.Error(ex, "Failed to set up an accepted connection.");
	}

	
	public async ValueTask DisposeAsync()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 1)
		{
			return;
		}

		// Order matters. Stop accepting first so no new connection joins the set, then tear the existing ones
		// down while the workers are still running so their queued frames get dispatched and their pooled
		// buffers go back, and only then stop the workers.
		SocketTransport.Close(_socket);

		if (_acceptLoop is not null)
		{
			try
			{
				await _acceptLoop.ConfigureAwait(false);
			}
			catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
			{
			}
		}

		await Task.WhenAll(_connections.Values.Select(static connection => connection.DisposeAsync().AsTask()))
			.ConfigureAwait(false);

		await _host.DisposeAsync().ConfigureAwait(false);

		_slots.Dispose();
	}
}
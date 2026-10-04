using Myethos.Network.Exchanging;
using Serilog;

namespace Myethos.Network.Communication;

/// <summary>
///     One client connection: a pooled receive buffer, a directional cipher, a bounded ordered inbound
///     queue, and a batching outbound pipeline.
/// </summary>
/// <remarks>
///     <para><b>Stream invariant.</b> The cipher is stateful and TCP is a byte stream, so the one rule
///     that matters is that bytes are decrypted exactly once, in arrival order. Every receive decrypts
///     only the slice that just arrived, never the leftover at the front of the buffer, and the splitter
///     always runs on already-decrypted bytes.</para>
///     <para><b>Exchange invariant.</b> The 6609 exchange frame carries its length at offset 7 and the
///     declared value does not count those 7 bytes, so the frame is <c>u16@7 + 7</c> bytes long. Only
///     the first 9 bytes are decrypted in order to read that field; decrypting further up front would
///     advance the keystream past the frame and desynchronise everything after it.</para>
///     <para><b>Task shape.</b> Exactly one task per connection: the receive loop, which is the only thing
///     that has to read that particular socket. Inbound dispatch and outbound writes run on the host's
///     pooled workers, partitioned so that neither direction can stall the other. That is the difference
///     from the per-connection-loop version, which spent three tasks per client.</para>
///     <para><b>Cost shape.</b> Steady-state inbound processing allocates nothing: the receive buffer
///     comes from a pool, a drained region is lifted with a single <c>memcpy</c> and handed over as
///     slices of one pooled array, and the outbound pipeline merges a burst of frames into one socket
///     write.</para>
/// </remarks>
public sealed class ClientConnection : IAsyncDisposable
{
	private static readonly ILogger Logger = Log.ForContext(typeof(ClientConnection));

	private readonly ConnectionHost _host;
	private readonly NetworkServerOptions _options;
	private readonly IPacketSplitter _splitter;
	private readonly IConnectionSession _session;
	private readonly Socket _socket;
	private readonly byte[] _footer;

	private readonly WorkQueue<PacketBatch> _inbound;
	private readonly WorkQueue<OutboundFrame> _outbound;
	private readonly InboundChannel _inboundChannel;
	private readonly OutboundChannel _outboundChannel;

	private readonly ActivityGate _dispatchGate = new();
	private readonly ActivityGate _writeGate = new();
	private readonly CancellationTokenSource _idle;
	private readonly CancellationTokenSource _lifetime;

	private byte[] _staging = [];
	private int _staged;
	private byte[] _buffer;
	private int _received;
	private int _pendingFrames;

	private List<TaskCompletionSource>? _flushWaiters;

	private int _disposed;
	private int _stage = (int)ConnectionStage.Connected;
	private int _tornDown;

	internal ClientConnection(long id, string remoteAddress, Socket socket, ConnectionHost host, IConnectionSession session)
	{
		Id = id;
		RemoteAddress = remoteAddress;
		_socket = socket;
		_host = host;
		_session = session;
		_options = host.Options;
		_splitter = host.Splitter;
		_footer = host.Footer;

		_buffer = host.Buffers.Rent();

		// Bounded on purpose. A slow game-logic handler should stall the receive loop, which closes the
		// TCP window and pushes back on the client instead of growing the queue without bound and ending
		// as an out-of-memory kill.
		_inbound = new WorkQueue<PacketBatch>(_options.InboundQueueCapacity);
		_outbound = new WorkQueue<OutboundFrame>(_options.OutboundQueueCapacity);

		_inboundChannel = new InboundChannel(_inbound, this);
		_outboundChannel = new OutboundChannel(_outbound, this);

		// One linked source for the whole connection: the listener's shutdown plus the idle reaper. Built
		// once, because a linked source per receive would allocate on the hottest path in the server.
		_idle = new CancellationTokenSource();
		_lifetime = CancellationTokenSource.CreateLinkedTokenSource(host.Shutdown, _idle.Token);

		// Staging is pooled and sized so that any legal frame fits even when the batch ceiling is smaller,
		// which is what lets the outbound worker flush mid-turn and retry instead of ever dropping a frame.
		_staging = ArrayPool<byte>.Shared.Rent(
			Math.Max(_options.MaxSendBatchBytes, _splitter.MaxFrameBytes + _footer.Length));
	}

	/// <summary>Monotonic identifier, unique for the lifetime of the process.</summary>
	public long Id { get; }

	/// <summary>Remote IPv4 address in string form.</summary>
	public string RemoteAddress { get; }

	/// <summary>Current lifecycle stage.</summary>
	public ConnectionStage Stage
	{
		get => (ConnectionStage)Volatile.Read(ref _stage);
		private set => Volatile.Write(ref _stage, (int)value);
	}

	/// <summary>
	///     Transport cipher. A game session replaces this inside its exchange handler, and the receive loop
	///     picks the new instance up immediately for any bytes trailing the exchange frame.
	/// </summary>
	public INetworkCipher Cipher { get; set; } = null!;

	/// <summary>Frames waiting in the inbound queue for a dispatch worker.</summary>
	public int Pending => Volatile.Read(ref _pendingFrames);

	/// <summary>Bytes staged for the next socket write.</summary>
	public int StagedBytes => Volatile.Read(ref _staged);

	/// <summary>True once teardown has been requested.</summary>
	public bool IsClosed => Volatile.Read(ref _tornDown) != 0;

	/// <summary>The session bound to this connection.</summary>
	public IConnectionSession Session => _session;

	#region send

	/// <summary>
	///     Queues an already-framed payload.
	/// </summary>
	/// <remarks>
	///     The first four bytes must be the header slot: the type goes at offset 2 and the size is written by
	///     the send path, so the value the caller placed at offset 0 is ignored. Everything after offset 4 is
	///     the body.
	///     <para>
	///         This returns as soon as the frame is queued. The socket write happens later on a pooled worker,
	///         merged with whatever else is queued, so a burst of N calls becomes one <c>send</c>. Use
	///         <see cref="SendAndFlushAsync" /> when the peer cannot answer before the bytes have actually
	///         left.
	///     </para>
	/// </remarks>
	/// <exception cref="ArgumentOutOfRangeException">The payload is smaller than a header or larger than the ceiling.</exception>
	public ValueTask SendAsync(byte[] packet, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(packet);

		return QueueFrame(new OutboundFrame(packet, flush: null, rented: false), cancellationToken);
	}

	/// <summary>Queues a payload from arbitrary memory, copying it into a pooled buffer.</summary>
	/// <exception cref="ArgumentOutOfRangeException">The payload is smaller than a header or larger than the ceiling.</exception>
	public ValueTask SendAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken = default)
	{
		byte[] copy = ArrayPool<byte>.Shared.Rent(packet.Length);
		packet.Span.CopyTo(copy);

		return QueueFrame(new OutboundFrame(copy, flush: null, rented: true), cancellationToken);
	}

	/// <summary>
	///     Queues a payload and completes only once its bytes have reached the socket. Used for the
	///     handshake, where the client cannot answer before the request has actually been sent and where the
	///     cipher swap that follows must not race ahead of it.
	/// </summary>
	public async ValueTask SendAndFlushAsync(byte[] packet, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(packet);

		ValidatePayload(packet.Length);

		TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

		if (Volatile.Read(ref _disposed) != 0)
		{
			return;
		}

		if (!_outbound.TryEnqueue(new OutboundFrame(packet, completion, rented: false)))
		{
			completion.TrySetCanceled();
			return;
		}

		SignalOutbound();

		await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Closes the connection. Teardown itself finishes on the receive loop.</summary>
	public void Disconnect() => Dispose();

	private ValueTask QueueFrame(OutboundFrame frame, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		ValidatePayload(frame.Payload.Length);

		// A closed connection is not an error: callers such as the idle sweep and the disconnect handler
		// legitimately race with teardown, and dropping the frame is the correct outcome.
		if (Volatile.Read(ref _disposed) != 0)
		{
			frame.ReleaseRented();
			return default;
		}

		// The outbound queue is bounded and never back-pressured, because a send cannot wait. A full queue
		// means the peer has stopped reading, which means the connection is dead; closing it is cheaper and
		// more honest than growing memory on its behalf.
		if (!_outbound.TryEnqueue(frame))
		{
			frame.ReleaseRented();
			frame.Flush?.TrySetCanceled();
			ProtocolError("outbound queue overflow");
			return default;
		}

		SignalOutbound();
		return default;
	}

	/// <summary>
	///     Hands this connection to its outbound worker, but only if no wake-up is already outstanding.
	/// </summary>
	/// <remarks>
	///     The one-token rule is what keeps the wake channel from filling with an entry per frame: a client
	///     that queues fifty frames while the worker is busy still leaves exactly one entry behind.
	/// </remarks>
	private void SignalOutbound()
	{
		if (_outboundChannel.ArmToken())
		{
			OutboundPartition?.Wake.Writer.TryWrite(this);
		}
	}

	#endregion

	#region lifecycle

	/// <summary>
	///     Runs the whole connection: session handshake, optional key exchange, then the receive loop until
	///     the peer goes away or the server tears it down.
	/// </summary>
	internal async Task RunAsync()
	{
		CancellationToken cancellationToken = _lifetime.Token;

		try
		{
			Stage = ConnectionStage.Handshaking;

			await _session.OnConnectedAsync(this, cancellationToken).ConfigureAwait(false);

			if (_options.ExchangeHandshake is { } exchange &&
				!await ExchangeAsync(exchange, cancellationToken).ConfigureAwait(false))
			{
				return;
			}

			Stage = ConnectionStage.Established;

			await ReceiveLoopAsync(cancellationToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
		}
		catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
		{
		}
		catch (Exception ex)
		{
			_options.UnhandledFault?.Invoke(this, ex);
		}
		finally
		{
			await ShutdownAsync().ConfigureAwait(false);
		}
	}

	/// <summary>Requests teardown. The receive loop finishes it and returns the buffers.</summary>
	public void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 1)
		{
			return;
		}

		Stage = ConnectionStage.Disconnecting;

		try
		{
			_idle.Cancel();
		}
		catch (ObjectDisposedException)
		{
			// Already torn down.
		}

		_outbound.Complete();
		SocketTransport.Close(_socket);
	}

	
	public async ValueTask DisposeAsync()
	{
		Dispose();
		await ShutdownAsync().ConfigureAwait(false);
		GC.SuppressFinalize(this);
	}

	private async ValueTask ShutdownAsync()
	{
		if (Interlocked.Exchange(ref _tornDown, 1) == 1)
		{
			return;
		}

		Stage = ConnectionStage.Closed;
		Volatile.Write(ref _disposed, 1);

		SocketTransport.Close(_socket);
		_outbound.Complete();
		_inbound.Complete();

		// Stop the inbound worker and wait for it, so nothing can be inside a handler while the leftover
		// frames are finished and the disconnect is reported. The wait is bounded: a worker parked on a
		// socket write against a closed socket returns immediately, and a hung one must not stop the
		// server from releasing this connection's buffers.
		await SettleAsync(_dispatchGate).ConfigureAwait(false);
		await SettleAsync(_writeGate).ConfigureAwait(false);

		// Whatever is still queued will never reach the wire. A pooled payload has to go back or it leaks
		// for the process lifetime, and a flush acknowledgement left unsettled would strand whoever is
		// awaiting it - typically the handshake, which is why the cancellation is what settles them.
		_outbound.DiscardAll(static frame =>
		{
			frame.ReleaseRented();
			frame.Flush?.TrySetCanceled();
		});

		SettleFlushWaiters(completed: false);

		// Deliver whatever was already decoded before reporting the disconnect, so a session can release
		// character state it may have already published to the world.
		while (_inbound.TryDequeue(out PacketBatch batch))
		{
			try
			{
				await ProcessBatchAsync(batch, CancellationToken.None).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				ReportHandlerFault(ex);
			}
			finally
			{
				ReleaseBatch(batch);
			}
		}

		try
		{
			await _session.OnDisconnectedAsync(this).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			ReportHandlerFault(ex);
		}

		_host.Detach(this);

		_staged = 0;

		if (_staging.Length > 0)
		{
			ArrayPool<byte>.Shared.Return(_staging, clearArray: false);
			_staging = [];
		}

		// A grown buffer has the wrong length for the pool and is simply dropped; recycling it would hand a
		// mismatched size to the next connection.
		_host.Buffers.Return(_buffer);

		_lifetime.Dispose();
		_idle.Dispose();
	}

	private static async ValueTask SettleAsync(ActivityGate gate)
	{
		try
		{
			await gate.Idle.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
		}
		catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
		{
			// The owning worker is wedged. Drop the connection anyway rather than pinning its buffer.
		}
	}

	#endregion

	#region receive

	private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
	{
		Stage = ConnectionStage.Receiving;

		while (!cancellationToken.IsCancellationRequested && Volatile.Read(ref _disposed) == 0)
		{
			if (!Reserve())
			{
				return;
			}

			ArmIdleTimeout(_options.ReceiveIdleTimeoutSeconds);

			int read;

			try
			{
				read = await _socket
					.ReceiveAsync(_buffer.AsMemory(_received), SocketFlags.None, cancellationToken)
					.ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				if (!_host.Shutdown.IsCancellationRequested && Volatile.Read(ref _disposed) == 0)
				{
					ProtocolError("receive idle timeout");
				}

				return;
			}
			catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
			{
				return;
			}

			if (read <= 0)
			{
				return;
			}

			// Only the bytes that just arrived get decrypted. Anything still sitting at the front of the
			// buffer was decrypted on an earlier pass and must not be touched again.
			Span<byte> fresh = _buffer.AsSpan(_received, read);
			Cipher.Decrypt(fresh, fresh);

			_received += read;

			if (!await ExtractAsync(cancellationToken).ConfigureAwait(false))
			{
				return;
			}
		}
	}

	/// <summary>
	///     Cuts every complete frame out of the receive buffer and lifts them into one pooled batch: a
	///     single copy per drained region rather than per frame.
	/// </summary>
	private async ValueTask<bool> ExtractAsync(CancellationToken cancellationToken)
	{
		int offset = 0;
		int frames = 0;

		while (offset < _received)
		{
			PacketSplitState state = _splitter.Split(
				_buffer.AsSpan(offset, _received - offset),
				out int payloadLength,
				out int consumed);

			if (state == PacketSplitState.NeedMore)
			{
				break;
			}

			if (state == PacketSplitState.Invalid ||
				!_splitter.VerifyFooter(_buffer.AsSpan(offset, consumed), payloadLength))
			{
				ProtocolError(state == PacketSplitState.Invalid ? "malformed frame length" : "invalid frame footer");
				return false;
			}

			offset += consumed;
			frames++;
		}

		if (frames == 0)
		{
			return true;
		}

		byte[] batch = ArrayPool<byte>.Shared.Rent(offset);
		_buffer.AsSpan(0, offset).CopyTo(batch);

		int leftover = _received - offset;
		if (leftover > 0)
		{
			Buffer.BlockCopy(_buffer, offset, _buffer, 0, leftover);
		}

		_received = leftover;

		var packetBatch = new PacketBatch(batch, offset, frames);

		try
		{
			// Awaiting here is the backpressure: it suspends the read loop, which stops draining the socket
			// and lets the peer's send window close.
			await _inbound.EnqueueAsync(packetBatch, cancellationToken).ConfigureAwait(false);
		}
		catch
		{
			ArrayPool<byte>.Shared.Return(batch, clearArray: false);
			throw;
		}

		Interlocked.Add(ref _pendingFrames, frames);
		_dispatchGate.Invalidate();

		if (_inboundChannel.ArmToken())
		{
			InboundPartition?.Wake.Writer.TryWrite(this);
		}

		return true;
	}

	private async ValueTask<bool> ExchangeAsync(ExchangeOptions exchange, CancellationToken cancellationToken)
	{
		Stage = ConnectionStage.Exchanging;

		int headerSize = exchange.HeaderSize;
		int offset = exchange.LengthOffset;

		ArmIdleTimeout(_options.ExchangeTimeoutSeconds > 0
			? _options.ExchangeTimeoutSeconds
			: exchange.TimeoutSeconds);

		if (!await FillAsync(headerSize, cancellationToken).ConfigureAwait(false))
		{
			return false;
		}

		// Exactly nine bytes: enough to read the length, no more. Decrypting further here would push the
		// keystream past this frame and desynchronise every byte that follows it.
		Span<byte> head = _buffer.AsSpan(0, headerSize);
		Cipher.Decrypt(head, head);

		int declared = FrameHeader.ReadLength(_buffer.AsSpan(offset));
		int consumed = declared + offset;

		if (consumed < headerSize ||
			declared > exchange.MaxExchangeBytes ||
			consumed > _splitter.MaxFrameBytes)
		{
			ProtocolError("exchange frame length out of range");
			return false;
		}

		if (consumed > _received && !await FillAsync(consumed, cancellationToken).ConfigureAwait(false))
		{
			return false;
		}

		if (consumed > headerSize)
		{
			Span<byte> body = _buffer.AsSpan(headerSize, consumed - headerSize);
			Cipher.Decrypt(body, body);
		}

		ExchangeResult result;

		try
		{
			result = await _session
				.OnExchangeAsync(this, _buffer.AsMemory(0, consumed), cancellationToken)
				.ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			ReportHandlerFault(ex);
			return false;
		}

		if (!result.Success)
		{
			ProtocolError("exchange rejected by session");
			return false;
		}

		// The session installed the negotiated cipher before returning, and the client already sent whatever
		// followed the exchange frame using it, so decrypt the tail with the new key.
		int leftover = _received - consumed;
		if (leftover > 0)
		{
			Buffer.BlockCopy(_buffer, consumed, _buffer, 0, leftover);
			_received = leftover;

			Span<byte> tail = _buffer.AsSpan(0, leftover);
			Cipher.Decrypt(tail, tail);

			if (!await ExtractAsync(cancellationToken).ConfigureAwait(false))
			{
				return false;
			}
		}
		else
		{
			_received = 0;
		}

		if (!result.Response.IsEmpty)
		{
			await SendAndFlushAsync(result.Response.ToArray(), cancellationToken).ConfigureAwait(false);
		}

		return true;
	}

	/// <summary>Reads without decrypting until at least <paramref name="required" /> bytes are buffered.</summary>
	private async ValueTask<bool> FillAsync(int required, CancellationToken cancellationToken)
	{
		while (_received < required)
		{
			if (_received >= _buffer.Length && !Reserve())
			{
				return false;
			}

			ArmIdleTimeout(_options.ReceiveIdleTimeoutSeconds);

			int read;

			try
			{
				read = await _socket
					.ReceiveAsync(_buffer.AsMemory(_received), SocketFlags.None, cancellationToken)
					.ConfigureAwait(false);
			}
			catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
			{
				return false;
			}

			if (read <= 0)
			{
				return false;
			}

			_received += read;
		}

		return true;
	}

	/// <summary>Grows the receive buffer, or reports failure once the frame ceiling is reached.</summary>
	private bool Reserve()
	{
		if (_received < _buffer.Length)
		{
			return true;
		}

		int ceiling = _splitter.MaxFrameBytes;

		if (_buffer.Length >= ceiling)
		{
			ProtocolError("receive buffer exhausted without a complete frame");
			return false;
		}

		byte[] grown = new byte[Math.Min(_buffer.Length * 2, ceiling)];
		Buffer.BlockCopy(_buffer, 0, grown, 0, _received);
		_buffer = grown;
		return true;
	}

	/// <summary>
	///     Rearms the idle reaper. The cost of a half-open connection is a buffer and a parked task held for
	///     as long as the OS tolerates it, which on Windows is two hours by default.
	/// </summary>
	private void ArmIdleTimeout(int seconds)
	{
		if (seconds <= 0)
		{
			return;
		}

		try
		{
			_idle.CancelAfter(TimeSpan.FromSeconds(seconds));
		}
		catch (ObjectDisposedException)
		{
			// Torn down between the loop check and the arm.
		}
	}

	#endregion

	#region inbound plumbing

	/// <summary>
	///     Splits one decoded region back into individual frames and hands each to the session. The splitter
	///     runs on a span that never outlives this frame boundary, so the loop body holds no ref struct
	///     across the await.
	/// </summary>
	internal async ValueTask ProcessBatchAsync(PacketBatch batch, CancellationToken cancellationToken)
	{
		int offset = 0;

		while (offset < batch.Length)
		{
			PacketSplitState state = _splitter.Split(
				batch.Array.AsSpan(offset, batch.Length - offset),
				out int payloadLength,
				out int consumed);

			if (state != PacketSplitState.Complete)
			{
				// Batches are produced by the same splitter, so anything else here means the pooled array was
				// recycled early. Stop rather than hand the session garbage.
				ProtocolError("inconsistent batch framing");
				return;
			}

			await _session
				.OnPacketAsync(this, batch.Array.AsMemory(offset, payloadLength), cancellationToken)
				.ConfigureAwait(false);

			offset += consumed;
		}
	}

	private void ReleaseBatch(PacketBatch batch)
	{
		Interlocked.Add(ref _pendingFrames, -batch.Frames);
		ArrayPool<byte>.Shared.Return(batch.Array, clearArray: false);
	}

	/// <summary>Raised for any exception escaping a session handler.</summary>
	internal void ReportHandlerFault(Exception exception)
	{
		if (_options.UnhandledFault is { } handler)
		{
			try
			{
				handler(this, exception);
			}
			catch (Exception ex)
			{
				Logger.Error(ex, "Unhandled fault while reporting {Fault}.", exception.GetType().Name);
			}
		}
		else
		{
			Logger.Error(exception, "Unhandled fault on connection {ConnectionId}.", Id);
		}
	}

	private void ProtocolError(string reason)
	{
		try
		{
			_options.OnProtocolError?.Invoke(this, reason);
		}
		catch (Exception ex)
		{
			Logger.Error(ex, "Unhandled fault in the protocol error handler.");
		}

		Logger.Debug("{Reason} on connection {ConnectionId} from {RemoteAddress}.", reason, Id, RemoteAddress);

		Dispose();
	}

	private void ValidatePayload(int length)
	{
		if (length < FrameHeader.MinimumReadable || length > _splitter.MaxFrameSize)
		{
			throw new ArgumentOutOfRangeException(
				nameof(length),
				length,
				$"Payload must be between {FrameHeader.MinimumReadable} and {_splitter.MaxFrameSize} bytes.");
		}
	}

	#endregion

	#region send pipeline

	/// <summary>
	///     Copies one queued frame into the staging buffer.
	/// </summary>
	/// <remarks>
	///     Staging is what turns a burst of sends into a single write. The cipher is a continuous stream, so
	///     encrypting several frames as one contiguous block at the end of the turn is byte-identical to
	///     encrypting them one at a time - which is the only reason batching is safe here at all.
	/// </remarks>
	internal async ValueTask StageOutboundAsync(OutboundFrame frame, CancellationToken cancellationToken)
	{
		int needed = frame.Payload.Length + _footer.Length;

		// A frame wider than the batch ceiling still has to go out. The staging buffer is sized to hold any
		// legal frame, so flushing here and retrying always succeeds; the only cost is one extra syscall.
		if (_staged + needed > _staging.Length && !await FlushStagedAsync(cancellationToken).ConfigureAwait(false))
		{
			frame.ReleaseRented();
			frame.Flush?.TrySetCanceled();
			return;
		}

		frame.Payload.CopyTo(_staging.AsSpan(_staged));

		// The size counts itself but not the footer, and the caller only had to supply the type.
		FrameHeader.WriteLength(_staging.AsSpan(_staged), frame.Payload.Length);
		_footer.CopyTo(_staging.AsSpan(_staged + frame.Payload.Length));

		_staged += needed;

		if (frame.Flush is { } waiter)
		{
			(_flushWaiters ??= []).Add(waiter);
		}
	}

	/// <summary>Encrypts and writes everything staged for this turn, in one call.</summary>
	/// <returns>Whether the bytes reached the socket.</returns>
	internal async ValueTask<bool> FlushStagedAsync(CancellationToken cancellationToken)
	{
		int used = _staged;

		if (used <= 0)
		{
			return true;
		}

		_staged = 0;

		Memory<byte> region = _staging.AsMemory(0, used);
		Cipher.Encrypt(region.Span, region.Span);

		bool written = await SocketTransport.SendAllAsync(_socket, region, cancellationToken).ConfigureAwait(false);

		SettleFlushWaiters(written);

		if (!written)
		{
			ProtocolError("socket write failed");
		}

		return written;
	}

	/// <summary>
	///     Settles every handshake-style flush acknowledgement collected during the turn just written.
	/// </summary>
	private void SettleFlushWaiters(bool completed)
	{
		if (_flushWaiters is not { Count: > 0 } waiters)
		{
			return;
		}

		_flushWaiters = null;

		foreach (TaskCompletionSource waiter in waiters)
		{
			if (completed)
			{
				waiter.TrySetResult();
			}
			else
			{
				waiter.TrySetCanceled();
			}
		}
	}

	#endregion

	#region nested

	/// <summary>A payload waiting to be written, optionally carrying a flush acknowledgement.</summary>
	internal sealed class OutboundFrame
	{
		private readonly bool _rented;
		private byte[]? _payload;

		public OutboundFrame(byte[] payload, TaskCompletionSource? flush, bool rented)
		{
			_payload = payload;
			_rented = rented;
			Flush = flush;
		}

		public TaskCompletionSource? Flush { get; }

		public byte[] Payload => _payload ?? throw new ObjectDisposedException(nameof(OutboundFrame));

		/// <summary>Returns a pooled payload to the pool. A caller-owned array is left alone.</summary>
		public void ReleaseRented()
		{
			byte[]? payload = Interlocked.Exchange(ref _payload, null);

			if (_rented && payload is not null)
			{
				ArrayPool<byte>.Shared.Return(payload, clearArray: false);
			}
		}
	}

	/// <summary>Adapts the inbound queue to the scheduler, and tracks handler activity for teardown.</summary>
	private sealed class InboundChannel(WorkQueue<PacketBatch> queue, ClientConnection owner) : IWorkChannel<PacketBatch>
	{
		public bool HasWork => queue.HasWork;

		public bool TryDequeue(out PacketBatch item) => queue.TryDequeue(out item);

		public bool ArmToken() => queue.ArmToken();

		public void BeginTurn() => owner._dispatchGate.Enter();

		public void EndTurn() => owner._dispatchGate.Exit();

		public void ClearToken() => queue.ClearToken();
	}

	/// <summary>Adapts the outbound queue to the scheduler, and tracks staging activity for teardown.</summary>
	private sealed class OutboundChannel(WorkQueue<OutboundFrame> queue, ClientConnection owner) : IWorkChannel<OutboundFrame>
	{
		public bool HasWork => queue.HasWork;

		public bool TryDequeue(out OutboundFrame item) => queue.TryDequeue(out item);

		public bool ArmToken() => queue.ArmToken();

		public void BeginTurn() => owner._writeGate.Enter();

		public void EndTurn() => owner._writeGate.Exit();

		public void ClearToken() => queue.ClearToken();
	}

	#endregion

	#region scheduler surface

	internal IWorkChannel<PacketBatch> Inbound => _inboundChannel;

	internal IWorkChannel<OutboundFrame> Outbound => _outboundChannel;

	internal WorkScheduler<PacketBatch>.Partition? InboundPartition { get; set; }

	internal WorkScheduler<OutboundFrame>.Partition? OutboundPartition { get; set; }

	#endregion
}
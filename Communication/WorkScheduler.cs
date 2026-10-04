using Serilog;

namespace Myethos.Network.Communication;

/// <summary>
///     Pooled workers that run per-connection work items: inbound batches on the way to the session
///     handler, outbound frames on the way to the socket.
/// </summary>
/// <remarks>
///     <para><b>Why a pool and not a loop per connection.</b> The per-connection design spends three
///     tasks per client: a receive loop, a dispatch loop, and a write loop. At a few thousand
///     connections that is tens of thousands of <see cref="Task" /> objects, each pinning a state
///     machine, a continuation and a slot in the thread pool's queue even while it is parked on an
///     <c>await" /> that will not complete for seconds. Here the receive loop is the only per-connection
///     task, and it is the one task that genuinely has to exist, because it is the only thing reading
///     that socket. Everything else is pooled across all connections, in both directions.</para>
///     <para><b>Partitions.</b> A connection is assigned one partition per direction at accept, chosen
///     by least population, and each partition owns exactly one worker. A connection belongs to exactly
///     one partition, which makes three properties structural rather than defended:
///     <list type="bullet">
///         <item><description>
///             Inbound work for one connection never overlaps with itself, so frames reach the session in
///             strict wire order without a claim flag, a sequence number or a compare-and-swap.
///         </description></item>
///         <item><description>
///             Outbound work for one connection is likewise serialised, which is what allows the cipher to
///             be touched by one thread at a time and a burst of frames to be encrypted as one contiguous
///             block instead of one call per frame.
///         </description></item>
///         <item><description>
///             The two directions get separate schedulers, so a slow session handler can never stall a
///             socket write, and a slow socket write can never stall a session handler.
///         </description></item>
///     </list>
///     </para>
///     <para><b>Fairness.</b> A worker drains one connection's queue only up to
///     <c>MaxWorkItemsPerTurn</c> items, then re-queues that connection at the back. A flooding client
///     therefore cannot monopolise a partition and add latency to every other player sharing it. On the
///     outbound side the same budget is what makes batching work: the turn ends with one flush, so N
///     queued frames become one socket write.</para>
/// </remarks>
internal sealed class WorkScheduler<TItem> : IAsyncDisposable
{
	private static readonly ILogger Logger = Log.ForContext(typeof(WorkScheduler<TItem>));

	private readonly Partition[] _partitions;
	private readonly Task[] _workers;
	private readonly Func<ClientConnection, IWorkChannel<TItem>> _channels;
	private readonly Func<ClientConnection, TItem, CancellationToken, ValueTask> _process;
	private readonly Func<ClientConnection, CancellationToken, ValueTask> _flush;
	private readonly CancellationTokenSource _shutdown = new();

	private readonly int _budget;
	private int _disposed;

	/// <param name="options">Supplies the partition count and the per-turn fairness budget.</param>
	/// <param name="channels">Returns the channel the scheduler drives for a given connection.</param>
	/// <param name="process">Runs one work item for one connection.</param>
	/// <param name="flush">Called once at the end of a turn that processed anything.</param>
	public WorkScheduler(
		NetworkServerOptions options,
		Func<ClientConnection, IWorkChannel<TItem>> channels,
		Func<ClientConnection, TItem, CancellationToken, ValueTask> process,
		Func<ClientConnection, CancellationToken, ValueTask> flush)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(channels);
		ArgumentNullException.ThrowIfNull(process);
		ArgumentNullException.ThrowIfNull(flush);

		options.Validate();

		_channels = channels;
		_process = process;
		_flush = flush;
		_budget = options.MaxWorkItemsPerTurn;

		int count = Math.Max(1, options.WorkPartitions);

		_partitions = new Partition[count];
		_workers = new Task[count];

		for (int i = 0; i < count; i++)
		{
			// Captured in a local rather than by reading the loop variable inside the lambda: a closure over
			// 'i' would evaluate it when the task body finally runs, by which point the loop has moved on and
			// every worker reads the same out-of-range index. The failure is deferred to the thread pool, so
			// it surfaces later as a faulted task during DisposeAsync rather than as a clear fault here.
			Partition partition = new Partition(i);

			_partitions[i] = partition;
			_workers[i] = Task.Run(() => WorkerAsync(partition, _shutdown.Token), CancellationToken.None);
		}
	}

	/// <summary>Number of partitions, each with exactly one worker.</summary>
	public int Partitions => _partitions.Length;

	/// <summary>
	///     Registers a connection and returns the partition that will handle it.
	/// </summary>
	/// <remarks>
	///     Least-populated wins, with a randomised starting point. The reference implementation scans
	///     partitions in array order and increments a weight, which fills partition zero first and only
	///     spills over once it is full; starting the scan at a per-accept offset spreads a burst of
	///     simultaneous accepts across every partition immediately instead of making the first
	///     <c>WorkPartitions</c> clients queue behind a single worker.
	/// </remarks>
	public Partition Assign(ClientConnection connection)
	{
		ArgumentNullException.ThrowIfNull(connection);

		int offset = Random.Shared.Next(_partitions.Length);
		int bestLoad = int.MaxValue;
		Partition best = _partitions[offset];

		for (int i = 0; i < _partitions.Length; i++)
		{
			Partition candidate = _partitions[(offset + i) % _partitions.Length];
			int load = Volatile.Read(ref candidate.Load);

			if (load < bestLoad)
			{
				best = candidate;
				bestLoad = load;

				if (load == 0)
				{
					break;
				}
			}
		}

		Interlocked.Increment(ref best.Load);
		return best;
	}

	/// <summary>Returns a partition's load after its connection has gone away.</summary>
	public void Release(Partition? partition)
	{
		if (partition is not null)
		{
			Interlocked.Decrement(ref partition.Load);
		}
	}

	private async Task WorkerAsync(Partition partition, CancellationToken cancellationToken)
	{
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				bool worked = false;

				// Drain whatever wake-ups are already queued before parking. Bounded by the channel rather
				// than an unbounded loop, so a flood of enqueues cannot starve cancellation.
				while (partition.Wake.Reader.TryRead(out ClientConnection? connection))
				{
					if (connection is null)
					{
						continue;
					}

					worked |= await RunTurnAsync(connection, partition, cancellationToken).ConfigureAwait(false);
				}

				if (worked)
				{
					continue;
				}

				try
				{
					await partition.Wake.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException)
				{
					return;
				}
			}
		}
		catch (Exception ex) when (ex is OperationCanceledException or ChannelClosedException)
		{
		}
		catch (Exception ex)
		{
			// A worker that dies takes its whole partition's work with it, so this is logged at error level
			// rather than swallowed.
			Logger.Error(ex, "Work scheduler partition {Partition} stopped unexpectedly.", partition.Index);
		}
	}

	/// <summary>
	///     Runs up to the per-turn budget of one connection's items, then flushes once.
	/// </summary>
	/// <returns>Whether any item was processed.</returns>
	private async ValueTask<bool> RunTurnAsync(ClientConnection connection, Partition partition, CancellationToken cancellationToken)
	{
		IWorkChannel<TItem> channel = _channels(connection);
		int processed = 0;

		channel.BeginTurn();

		try
		{
			while (processed < _budget && channel.TryDequeue(out TItem item))
			{
				await _process(connection, item, cancellationToken).ConfigureAwait(false);
				processed++;
			}
		}
		catch (Exception ex)
		{
			// A fault here must not strand the connection with work queued and no wake-up left, which is
			// what silently freezes a client for the rest of its session.
			Logger.Error(ex, "Unhandled fault processing work on partition {Partition}.", partition.Index);
		}
		finally
		{
			if (processed > 0)
			{
				try
				{
					await _flush(connection, cancellationToken).ConfigureAwait(false);
				}
				catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
				{
				}
				catch (Exception ex)
				{
					Logger.Error(ex, "Unhandled fault flushing work on partition {Partition}.", partition.Index);
				}
			}

			channel.EndTurn();

			// Disarm the wake token, then re-check. An enqueue that raced the disarm either saw the token
			// and skipped signalling - which is exactly why this re-check is not optional - or armed a
			// fresh one and signalled itself.
			channel.ClearToken();

			// Re-queueing at the back is the fairness mechanism: the connection goes behind everyone else
			// rather than holding the partition.
			if (channel.HasWork && !cancellationToken.IsCancellationRequested)
			{
				partition.Wake.Writer.TryWrite(connection);
			}
		}

		return processed > 0;
	}

	
	public async ValueTask DisposeAsync()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 1)
		{
			return;
		}

		await _shutdown.CancelAsync().ConfigureAwait(false);

		foreach (Partition partition in _partitions)
		{
			partition.Wake.Writer.TryComplete();
		}

		try
		{
			await Task.WhenAll(_workers).ConfigureAwait(false);
		}
		catch (Exception ex) when (ex is OperationCanceledException or ChannelClosedException)
		{
		}

		_shutdown.Dispose();
	}

	/// <summary>One worker plus the wake channel that feeds it.</summary>
	internal sealed class Partition
	{
		public Partition(int index)
		{
			Index = index;

			// Unbounded on purpose, and safe because of the one-token-per-connection rule enforced by
			// WorkQueue: a wake-up only exists while a connection has undispatched work.
			Wake = Channel.CreateUnbounded<ClientConnection>(new UnboundedChannelOptions
			{
				SingleReader = true,
				SingleWriter = false,
				AllowSynchronousContinuations = false
			});
		}

		public int Index { get; }

		public Channel<ClientConnection> Wake { get; }

		/// <summary>Live connections assigned here. Read and written with <see cref="Interlocked" />.</summary>
		public int Load;
	}
}
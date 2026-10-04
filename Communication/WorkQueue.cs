namespace Myethos.Network.Communication;

/// <summary>
///     One connection's bounded queue of work items, plus the single-token wake flag that lets a
///     pooled worker know there is something to collect.
/// </summary>
/// <remarks>
///     <para><b>The token rule.</b> The wake channel shared with the workers holds at most one entry per
///     connection, created on the transition from "nothing queued" to "something queued". Without that
///     rule a client that floods would leave one stale wake-up in the channel per frame, and the workers
///     would spend their budget reading entries for connections that are already empty.</para>
///     <para><b>The re-check rule.</b> Clearing the token and then re-reading the queue is mandatory,
///     not defensive. An enqueue that lands between the clear and the re-check sees the token already
///     set and skips signalling, so only the worker's own re-check can catch it. Get this wrong and the
///     connection stalls with a full queue and no wake-up, which is the hardest kind of transport bug to
///     reproduce because it needs a specific interleaving.</para>
/// </remarks>
internal sealed class WorkQueue<TItem>
{
	private readonly Channel<TItem> _channel;

	private int _tokenArmed;

	public WorkQueue(int capacity)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

		_channel = Channel.CreateBounded<TItem>(new BoundedChannelOptions(capacity)
		{
			SingleReader = true,
			SingleWriter = false,
			AllowSynchronousContinuations = false,
			FullMode = BoundedChannelFullMode.Wait
		});
	}

	/// <summary>Items waiting to be collected.</summary>
	public int Count => _channel.Reader.Count;

	/// <summary>Whether at least one item is waiting.</summary>
	public bool HasWork => _channel.Reader.Count > 0;

	/// <summary>Whether a wake token is currently outstanding for this queue.</summary>
	public bool IsTokenArmed => Volatile.Read(ref _tokenArmed) != 0;

	/// <summary>
	///     Enqueues without waiting.
	/// </summary>
	/// <returns>False when the queue is full or completed.</returns>
	public bool TryEnqueue(TItem item) => _channel.Writer.TryWrite(item);

	/// <summary>
	///     Enqueues, waiting for capacity. This is the backpressure: suspending the receive loop stops
	///     draining the socket, which lets the peer's send window close instead of letting the queue grow
	///     until the process runs out of memory.
	/// </summary>
	public ValueTask EnqueueAsync(TItem item, CancellationToken cancellationToken) =>
		_channel.Writer.WriteAsync(item, cancellationToken);

	/// <summary>Takes the next item, or false when the queue is drained.</summary>
	public bool TryDequeue(out TItem item) => _channel.Reader.TryRead(out item!);

	/// <summary>
	///     Arms the wake token.
	/// </summary>
	/// <returns>True when this call created the token, meaning the caller must signal the worker.</returns>
	public bool ArmToken() => Interlocked.Exchange(ref _tokenArmed, 1) == 0;

	/// <summary>Disarms the wake token. The caller must re-check <see cref="HasWork" /> afterwards.</summary>
	public void ClearToken() => Interlocked.Exchange(ref _tokenArmed, 0);

	/// <summary>
	///     Closes the queue for writing. Already-queued items remain readable, so a worker can still drain
	///     a batch that was accepted moments before teardown.
	/// </summary>
	public void Complete() => _channel.Writer.TryComplete();

	/// <summary>Discards everything still queued, handing each item to <paramref name="onDiscard" />.</summary>
	public void DiscardAll(Action<TItem>? onDiscard = null)
	{
		while (_channel.Reader.TryRead(out TItem? item))
		{
			if (item is not null)
			{
				onDiscard?.Invoke(item);
			}
		}
	}
}
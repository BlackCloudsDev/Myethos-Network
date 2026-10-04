namespace Myethos.Network.Communication;

/// <summary>
///     Non-generic view of one connection's work channel, used by <see cref="WorkScheduler{TItem}" /> to
///     drive it without knowing which direction or which queue it is looking at.
/// </summary>
internal interface IWorkChannel
{
	/// <summary>Whether at least one item is waiting.</summary>
	bool HasWork { get; }

	/// <summary>
	///     Arms the wake token.
	/// </summary>
	/// <returns>True when this call created the token, meaning the caller must signal the worker.</returns>
	bool ArmToken();

	/// <summary>Called on the worker just before the first item of a turn.</summary>
	void BeginTurn();

	/// <summary>Called on the worker after the last item of a turn, including when it faulted.</summary>
	void EndTurn();

	/// <summary>Disarms the wake token. The worker must re-check <see cref="HasWork" /> afterwards.</summary>
	void ClearToken();
}

/// <summary>One connection's work channel for a scheduler of <typeparamref name="TItem" />.</summary>
internal interface IWorkChannel<TItem> : IWorkChannel
{
	/// <summary>Takes the next item, or false when the queue is drained.</summary>
	bool TryDequeue(out TItem item);
}
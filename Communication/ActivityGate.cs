namespace Myethos.Network.Communication;

/// <summary>
///     Tracks whether a connection has work in flight, so teardown can wait for the last turn to finish
///     before reporting the disconnect.
/// </summary>
/// <remarks>
///     The invariant is that <see cref="Idle" /> completes only when nothing is running <i>and</i>
///     nothing has been queued since the last turn ended. It is maintained in exactly two places:
///     <see cref="Invalidate" /> on enqueue and <see cref="Exit" /> at the end of a turn. Anything that
///     tries to track the same condition by polling the queue length races with the worker and hangs on a
///     connection that was queued but never picked up.
/// </remarks>
internal sealed class ActivityGate
{
	private TaskCompletionSource _idle = new(TaskCreationOptions.RunContinuationsAsynchronously);

	private int _active;

	/// <summary>Whether nothing is running and nothing is queued.</summary>
	public bool IsIdle => Volatile.Read(ref _active) == 0 && Volatile.Read(ref _idle).Task.IsCompleted;

	/// <summary>Completes when the connection goes idle.</summary>
	public Task Idle => Volatile.Read(ref _idle).Task;

	/// <summary>Called when work is queued, because the connection is no longer idle.</summary>
	public void Invalidate()
	{
		if (Volatile.Read(ref _idle).Task.IsCompleted)
		{
			Volatile.Write(ref _idle, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
		}
	}

	/// <summary>Called by the owning worker before it touches the connection.</summary>
	public void Enter() => Interlocked.Increment(ref _active);

	/// <summary>Called by the owning worker when it is done with the connection.</summary>
	public void Exit()
	{
		if (Interlocked.Decrement(ref _active) == 0)
		{
			Volatile.Read(ref _idle).TrySetResult();
		}
	}
}
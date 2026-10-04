namespace Myethos.Network.Communication;

/// <summary>
///     Fixed-size pool of receive buffers, one rented per connection and returned on teardown.
/// </summary>
/// <remarks>
///     <para>
///         Buffers are recycled lock-free through a <see cref="ConcurrentStack{T}" />. A connection that
///         outgrew its buffer simply stops recycling it: growth is rare, and letting a grown buffer back
///         into the pool would hand a mismatched size to the next connection, which is a framing bug
///         that only shows up under load on a large frame.
///     </para>
///     <para>
///         Rented buffers are cleared on both rent and return. Only the first <c>Reserve</c> bytes of a
///         buffer are ever decrypted, so a stale tail from a previous tenant is not a correctness
///         problem, but it does leak one tenant's frame bytes into the next connection's buffer, which
///         is worth avoiding at a cost of one <c>memset</c> per connection lifetime.
///     </para>
/// </remarks>
internal sealed class BufferPool
{
	private readonly ConcurrentStack<byte[]> _buffers = new();
	private readonly int _bufferSize;

	public BufferPool(int bufferSize, int preallocate)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferSize);

		_bufferSize = bufferSize;
		Preallocated = Math.Max(0, preallocate);

		for (int i = 0; i < Preallocated; i++)
		{
			_buffers.Push(new byte[bufferSize]);
		}
	}

	/// <summary>Buffers created up front.</summary>
	public int Preallocated { get; }

	/// <summary>Buffers currently idle in the pool.</summary>
	public int Available => _buffers.Count;

	/// <summary>Buffers allocated because the pool ran dry; never returned.</summary>
	public int Overflow { get; private set; }

	/// <summary>Takes a cleared buffer, allocating one when the pool is empty.</summary>
	public byte[] Rent()
	{
		if (!_buffers.TryPop(out byte[]? buffer))
		{
			Overflow++;
			return GC.AllocateUninitializedArray<byte>(_bufferSize);
		}

		Array.Clear(buffer);
		return buffer;
	}

	/// <summary>Offers a buffer back. Buffers of an unexpected size are dropped, not recycled.</summary>
	public void Return(byte[]? buffer)
	{
		if (buffer is null || buffer.Length != _bufferSize)
		{
			return;
		}

		Array.Clear(buffer);
		_buffers.Push(buffer);
	}
}
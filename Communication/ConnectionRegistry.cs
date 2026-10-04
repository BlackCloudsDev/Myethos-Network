namespace Myethos.Network.Communication;

/// <summary>Why the registry refused a connection attempt.</summary>
public enum BlockReason
{
	/// <summary>The attempt was allowed.</summary>
	None,

	/// <summary>The address already holds the maximum number of live connections.</summary>
	MaxActiveConnections,

	/// <summary>The address exceeded its connection rate, or is currently banned.</summary>
	MaxConnectionAttempts
}

/// <summary>
///     Per-address connection accounting: a live-connection ceiling, a connection-rate ceiling, and
///     a temporary ban that follows from blowing through the rate.
/// </summary>
/// <remarks>
///     <para><b>Why both ceilings.</b> The live ceiling bounds how much of the server a single host can
///     occupy. The rate ceiling bounds how fast it can consume the accept budget: a client that
///     connects and drops in a loop never trips the live ceiling but still costs a socket, a buffer and
///     a task each time, so it is banned outright for a cooling-off period.</para>
///     <para><b>Address normalisation.</b> Every address goes through <c>MapToIPv4</c>. One host
///     presented as IPv4-mapped IPv6 otherwise receives a fresh budget for every connection, which
///     defeats the entire mechanism.</para>
///     <para><b>No timer.</b> The reference implementation clears all rate counters from a 60-second
///     timer and unblocks expired bans from the same sweep. That puts a global lock and a full
///     dictionary rebuild on a fixed cadence, and it unblocks everyone at the same instant. Here the
///     rate window and the ban expiry are both evaluated lazily against the clock, so an expired ban
///     lifts the moment it expires and the only sweep is an inline eviction pass that runs once the
///     table outgrows its cap.</para>
/// </remarks>
internal sealed class ConnectionRegistry
{
	private readonly ConcurrentDictionary<string, AddressRecord> _records = new();
	private readonly int _maxActivePerAddress;
	private readonly int _maxAttemptsPerWindow;
	private readonly int _banMilliseconds;
	private readonly int _windowMilliseconds;
	private readonly int _evictionThreshold;

	/// <param name="maxActivePerAddress">Live connections permitted from one address.</param>
	/// <param name="maxAttemptsPerWindow">Connection attempts permitted from one address per window.</param>
	/// <param name="banMinutes">Cooling-off minutes applied when the rate ceiling is exceeded.</param>
	/// <param name="windowSeconds">Length of the rate window.</param>
	public ConnectionRegistry(
		int maxActivePerAddress,
		int maxAttemptsPerWindow,
		int banMinutes,
		int windowSeconds = 60)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxActivePerAddress);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxAttemptsPerWindow);
		ArgumentOutOfRangeException.ThrowIfNegative(banMinutes);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(windowSeconds);

		_maxActivePerAddress = maxActivePerAddress;
		_maxAttemptsPerWindow = maxAttemptsPerWindow;
		_banMilliseconds = banMinutes * 60_000;
		_windowMilliseconds = windowSeconds * 1_000;

		// A thousand distinct addresses is generous for a game server and keeps the eviction pass
		// off the accept path in practice.
		_evictionThreshold = Math.Max(1024, maxActivePerAddress * 16);
	}

	/// <summary>Addresses currently holding a record.</summary>
	public int TrackedAddresses => _records.Count;

	/// <summary>Addresses currently banned.</summary>
	public int BannedAddresses
	{
		get
		{
			long now = Environment.TickCount64;
			int banned = 0;

			foreach (AddressRecord record in _records.Values)
			{
				if (Volatile.Read(ref record.BannedUntil) > now)
				{
					banned++;
				}
			}

			return banned;
		}
	}

	/// <summary>
	///     Evaluates one connection attempt.
	/// </summary>
	/// <param name="remote">The accepted socket's remote endpoint.</param>
	/// <param name="reason">The verdict, for logging.</param>
	/// <returns>Whether the attempt is allowed. On success a live-connection slot is reserved and must
	///     be handed back through <see cref="Release" />.</returns>
	public bool TryAcquire(IPEndPoint? remote, out BlockReason reason)
	{
		reason = BlockReason.None;

		if (remote is null)
		{
			reason = BlockReason.MaxConnectionAttempts;
			return false;
		}

		AddressRecord record = _records.GetOrAdd(remote.Address.MapToIPv4().ToString(), static _ => new AddressRecord());

		long now = Environment.TickCount64;

		if (Volatile.Read(ref record.BannedUntil) > now)
		{
			reason = BlockReason.MaxConnectionAttempts;
			return false;
		}

		// The rate check and the reservation happen under the record's own lock rather than a global
		// one. Contention here is only ever between connections from the same address, so a shared
		// dictionary lock would be pure overhead for every other client on the server.
		lock (record.Gate)
		{
			long windowStart = record.WindowStart;

			if (windowStart == 0 || now - windowStart >= _windowMilliseconds)
			{
				record.WindowStart = now;
				record.Attempts = 0;
			}

			if (++record.Attempts > _maxAttemptsPerWindow)
			{
				// Tripping the rate ceiling bans the address outright rather than merely refusing, which
				// is what turns a scripted reconnect loop from a cost into a non-event.
				record.BannedUntil = now + _banMilliseconds;
				reason = BlockReason.MaxConnectionAttempts;
				return false;
			}

			if (record.Active >= _maxActivePerAddress)
			{
				reason = BlockReason.MaxActiveConnections;
				return false;
			}

			record.Active++;
		}

		if (_records.Count > _evictionThreshold)
		{
			Evict(now);
		}

		return true;
	}

	/// <summary>Returns a live-connection slot reserved by <see cref="TryAcquire" />.</summary>
	public void Release(IPEndPoint? remote)
	{
		if (remote is null)
		{
			return;
		}

		if (_records.TryGetValue(remote.Address.MapToIPv4().ToString(), out AddressRecord? record) && record is not null)
		{
			Interlocked.Decrement(ref record.Active);
		}
	}

	/// <summary>Drops records whose ban has expired and which hold no live connections.</summary>
	private void Evict(long now)
	{
		foreach (KeyValuePair<string, AddressRecord> entry in _records)
		{
			AddressRecord record = entry.Value;

			if (Volatile.Read(ref record.Active) == 0 && Volatile.Read(ref record.BannedUntil) <= now)
			{
				_records.TryRemove(entry);
			}
		}
	}

	/// <summary>Mutable per-address state. Fields are guarded by <see cref="Gate" /> except where noted.</summary>
	private sealed class AddressRecord
	{
		public object Gate { get; } = new();

		public int Active;

		public int Attempts;

		public long WindowStart;

		/// <summary>Environment tick count at which the ban lapses. Zero means not banned.</summary>
		public long BannedUntil;
	}
}
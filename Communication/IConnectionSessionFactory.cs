namespace Myethos.Network.Communication;

/// <summary>
///     Creates one <see cref="IConnectionSession" /> per accepted connection.
/// </summary>
/// <remarks>
///     Sessions hold per-player state, so one instance is created per connection and never shared. An
///     implementation must be safe to call from the accept loop, which is single-threaded today but
///     carries no such guarantee.
/// </remarks>
public interface IConnectionSessionFactory
{
	/// <summary>Creates a session for a freshly accepted connection.</summary>
	IConnectionSession Create();
}
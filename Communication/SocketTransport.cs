using Serilog;

namespace Myethos.Network.Communication;

/// <summary>
///     Raw socket helpers that keep the framing layer free of transport boilerplate.
/// </summary>
internal static class SocketTransport
{
	/// <summary>Probes sent before Windows gives up on an idle connection.</summary>
	private const uint RetryCount = 3;

	private static readonly ILogger Logger = Log.ForContext(typeof(SocketTransport));

	/// <summary>
	///     Writes the whole span, looping over short writes.
	/// </summary>
	/// <remarks>
	///     A single <c>SendAsync</c> may legally write fewer bytes than requested; treating that as
	///     success drops the remainder of a frame on the floor and desynchronises the client with no
	///     local error at all. The only symptom is a client that stops responding after a large send,
	///     which is why this loops rather than trusting the first result.
	/// </remarks>
	/// <returns>Whether every byte reached the socket.</returns>
	public static async ValueTask<bool> SendAllAsync(Socket socket, ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
	{
		while (!buffer.IsEmpty)
		{
			int written;

			try
			{
				written = await socket.SendAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
			{
				return false;
			}

			if (written <= 0)
			{
				return false;
			}

			buffer = buffer[written..];
		}

		return true;
	}

	/// <summary>
	///     Applies the transport-level settings the server depends on: no Nagle delay, hard-close
	///     linger, sized OS buffers, and keepalive as a backstop for a peer that has gone away without a
	///     FIN.
	/// </summary>
	public static void ApplyDefaults(Socket socket, NetworkServerOptions options)
	{
		socket.NoDelay = options.NoDelay;
		socket.LingerState = new LingerOption(false, 0);

		if (options.SocketBufferSize > 0)
		{
			try
			{
				socket.SendBufferSize = options.SocketBufferSize;
				socket.ReceiveBufferSize = options.SocketBufferSize;
			}
			catch (SocketException)
			{
				// Some stacks clamp or refuse a hint; the defaults are still correct.
			}
		}

		if (options.KeepAliveSeconds > 0)
		{
			try
			{
				socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
			}
			catch (SocketException)
			{
				return;
			}

			if (OperatingSystem.IsWindows())
			{
				// Windows leaves the default two-hour probe interval, which is useless as a backstop for
				// a client that vanished without a FIN.
				EnableWindowsKeepAlive(socket, options.KeepAliveSeconds);
			}
		}
	}

	/// <summary>
	///     Configures the listening socket. Kept apart from <see cref="ApplyDefaults" /> because a
	///     listener has no peer and wants a deep backlog rather than buffer hints.
	/// </summary>
	public static void ApplyListenerDefaults(Socket socket, NetworkServerOptions options)
	{
		socket.LingerState = new LingerOption(false, 0);

		if (options.SocketBufferSize > 0)
		{
			try
			{
				socket.SendBufferSize = options.SocketBufferSize;
				socket.ReceiveBufferSize = options.SocketBufferSize;
			}
			catch (SocketException)
			{
			}
		}
	}

	/// <summary>Closes a socket without letting a pending send surface as a fault.</summary>
	public static void Close(Socket socket)
	{
		try
		{
			socket.Shutdown(SocketShutdown.Both);
		}
		catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
		{
			// The peer is already gone; disposing below is what actually closes it.
		}
		finally
		{
			try
			{
				socket.Dispose();
			}
			catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
			{
				Logger.Verbose(ex, "Socket already closed.");
			}
		}
	}

	/// <summary>
	///     Retunes the keepalive timers, which Windows otherwise leaves at a two-hour idle probe and a
	///     one-second interval.
	/// </summary>
	/// <remarks>
	///     <para>
	///         <c>SIO_KEEPALIVE_VALS</c> is four little-endian <c>ULONG</c> fields, sixteen bytes in total:
	///         <c>onoff</c>, <c>keepalivetime</c>, <c>keepaliveinterval</c>, <c>retrycount</c>. Each is
	///         written through <see cref="BinaryPrimitives" /> rather than by poking a byte into a
	///         collection initialiser, because a byte cast silently truncates anything past 255 and a short
	///         initialiser shifts every later field by four bytes - which is how the idle time ends up
	///         written into <c>onoff</c> and the connection probes every millisecond.
	///     </para>
	///     <para>
	///         The two time fields are in <b>milliseconds</b>. Where an older stack reads them as seconds the
	///         failure direction is safe rather than fatal: the probes simply arrive far less often than
	///         asked for. Writing seconds into a millisecond field has the opposite effect and floods the
	///         link, so the conversion is not optional.
	///     </para>
	/// </remarks>
	private static void EnableWindowsKeepAlive(Socket socket, int seconds)
	{
		if (seconds <= 0)
		{
			return;
		}

		try
		{
			// SIO_KEEPALIVE_VALS = 0x98000004.
			const int KeepAliveVals = unchecked((int)0x98000004);

			// Saturating: a caller asking for an absurd interval gets the largest representable one rather
			// than a wrapped, near-zero timeout.
			uint idleMilliseconds = (uint)Math.Min((long)seconds * 1_000L, uint.MaxValue);

			// Probe three times inside the idle window, and never more than once a second: a tighter interval
			// costs real traffic on a mobile link without detecting a dead peer any sooner.
			uint intervalMilliseconds = Math.Clamp(idleMilliseconds / 3, 1, 1_000);

			Span<byte> values = stackalloc byte[16];

			BinaryPrimitives.WriteUInt32LittleEndian(values[..4], 1);
			BinaryPrimitives.WriteUInt32LittleEndian(values[4..8], idleMilliseconds);
			BinaryPrimitives.WriteUInt32LittleEndian(values[8..12], intervalMilliseconds);
			BinaryPrimitives.WriteUInt32LittleEndian(values[12..16], RetryCount);

			socket.IOControl(KeepAliveVals, values.ToArray(), null);
		}
		catch (SocketException ex)
		{
			// Keepalive tuning is best-effort; the idle timeout is the real backstop.
			Logger.Verbose(ex, "Could not tune keepalive intervals.");
		}
	}
}
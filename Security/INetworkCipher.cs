namespace Myethos.Network.Security;

/// <summary>
///     A directional stream cipher. Both operations advance internal state, so a given cipher
///     instance must never be used concurrently from two threads, and the bytes passed through it
///     must be in wire order.
/// </summary>
/// <remarks>
///     <para><b>Ordering is the whole contract.</b> TCP is a byte stream and the cipher is stateful,
///     so the one rule that governs every use in this assembly is that bytes are decrypted exactly
///     once, in arrival order, and encrypted exactly once, in the order the frames were queued.</para>
///     <para><b>Concurrency.</b> A connection owns one cipher instance. The receive side is safe by
///     construction because only the receive loop ever decrypts. The send side is safe because the
///     outbound pipeline admits a single writer at a time, which is what lets a burst of frames be
///     encrypted as one contiguous block instead of one call per frame.</para>
/// </remarks>
public interface INetworkCipher
{
	/// <summary>
	///     Re-keys the cipher from positional seeds, which also restarts its directional streams.
	/// </summary>
	/// <remarks>
	///     "Restarts" is not universal and must not be assumed. <see cref="NetDragonCipher" /> rewinds
	///     only its outbound counter and deliberately leaves the inbound one counting, while
	///     <see cref="CastCipher" /> resets both registers and indexes together. Each implementation
	///     documents which of the two it does; the asymmetry is load-bearing, because the client keeps
	///     its own counters and rewinding the wrong one desynchronises the connection silently.
	/// </remarks>
	/// <param name="seeds">
	///     Positional seeds, in the order the implementation declares. <c>seeds[0]</c> is always the key
	///     material: a <see cref="ulong" /> access token for <see cref="NetDragonCipher" />, a
	///     <see cref="byte" /> array for <see cref="CastCipher" />. <see cref="CastCipher" /> also accepts
	///     a full <c>[key, encryptIV, decryptIV]</c> triple and ignores both IVs unless all three are
	///     present, because half a key schedule desynchronises the peer just as thoroughly as a wrong
	///     key does.
	/// </param>
	void GenerateKeys(params object[] seeds);

	/// <summary>Transforms server-to-client bytes in place or into <paramref name="destination" />.</summary>
	void Encrypt(Span<byte> source, Span<byte> destination);

	/// <summary>Transforms client-to-server bytes in place or into <paramref name="destination" />.</summary>
	void Decrypt(Span<byte> source, Span<byte> destination);
}
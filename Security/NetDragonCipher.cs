namespace Myethos.Network.Security;

/// <summary>
///     TQ Digital's counter-based XOR cipher, used on the login server (port 9959) and by any client
///     that has not completed a key exchange.
/// </summary>
/// <remarks>
///     <para>The cipher is deliberately asymmetric and this is not a bug:</para>
///     <list type="bullet">
///         <item><description><see cref="Encrypt" /> always uses the immutable <c>K1</c> table.</description></item>
///         <item><description>
///             <see cref="Decrypt" /> uses <c>K</c>, which is <c>K1</c> until <see cref="GenerateKeys" />
///             swaps in the token-derived <c>K2</c>.
///         </description></item>
///     </list>
///     <para>
///         This mirrors the client, which keeps a static outbound key and derives its inbound key
///         from the server-issued access token. Re-keying both directions from the token
///         desynchronises the client, and the symptom is always the same: the client connects, then
///         drops instantly.
///     </para>
///     <para><b>Keystream position.</b> Each direction counts bytes, not frames, and the counter is
///     advanced by <c>Add</c> <i>before</i> the bytes are consumed. That is why the count cannot be
///     taken from the frame count: two frames of different sizes leave the stream at different
///     positions, and merging them into one call is only correct because the counter walks the same
///     sequence of bytes either way.</para>
/// </remarks>
public sealed class NetDragonCipher : INetworkCipher
{
	/// <summary>Width of the keystream table.</summary>
	private const int TableSize = 0x200;

	/// <summary>
	///     The static IV seed from the client. Since it never changes across clients or
	///     instantiations, the table is computed once in the static constructor.
	/// </summary>
	private static ReadOnlySpan<byte> StaticSeed => [0x9D, 0x0F, 0xFA, 0x13, 0x62, 0x79, 0x5C, 0x6D];

	private static readonly byte[] StaticTable = BuildStaticTable();

	private readonly byte[] _staticKey = new byte[TableSize];
	private readonly byte[] _tokenKey = new byte[TableSize];

	private byte[] _inbound = null!;
	private ushort _inboundCounter;
	private ushort _outboundCounter;

	/// <summary>Creates a cipher keyed with the client's static tables.</summary>
	public NetDragonCipher()
	{
		Buffer.BlockCopy(StaticTable, 0, _staticKey, 0, TableSize);
		Buffer.BlockCopy(StaticTable, 0, _tokenKey, 0, TableSize);

		_inbound = _staticKey;
	}

	/// <summary>
	///     Derives the inbound keystream from the player's server access token.
	/// </summary>
	/// <remarks>
	///     Only the inbound table and its counter are re-keyed. The outbound stream stays on
	///     <c>K1</c> and keeps counting, because that is what the client does; re-keying it produces a
	///     well-formed but unreadable stream.
	/// </remarks>
	/// <param name="seeds">A single-element array holding the access token as a <see cref="ulong" />.</param>
	/// <exception cref="ArgumentException">The seed is absent or is not a <see cref="ulong" />.</exception>
	public void GenerateKeys(params object[] seeds)
	{
		ArgumentNullException.ThrowIfNull(seeds);

		if (seeds.Length == 0 || seeds[0] is not ulong token)
		{
			throw new ArgumentException(
				"NetDragonCipher expects a single ulong access token as the first seed.",
				nameof(seeds));
		}

		// The client's derivation splits the token into two halves and mixes them with the
		// constant 0x4321, then folds each half of the static table against the corresponding half of
		// the mixed value. The squaring is deliberately unsigned 32-bit wraparound, so MaskedInt32 is
		// load-bearing rather than a shortcut.
		uint a = (uint)(token >> 32);
		uint b = (uint)token;
		uint c = (a + b) ^ 0x4321 ^ a;
		uint d = c * c;

		Span<byte> first = stackalloc byte[4];
		Span<byte> second = stackalloc byte[4];

		BinaryPrimitives.WriteUInt32LittleEndian(first, c);
		BinaryPrimitives.WriteUInt32LittleEndian(second, d);

		for (int i = 0; i < 0x100; i++)
		{
			_tokenKey[i] = (byte)(_staticKey[i] ^ first[i & 3]);
			_tokenKey[i + 0x100] = (byte)(_staticKey[i + 0x100] ^ second[i & 3]);
		}

		_inbound = _tokenKey;
		_inboundCounter = 0;
	}

	
	public void Encrypt(Span<byte> source, Span<byte> destination) => Transform(source, destination, _staticKey, ref _outboundCounter);

	
	public void Decrypt(Span<byte> source, Span<byte> destination) => Transform(source, destination, _inbound, ref _inboundCounter);

	/// <summary>
	///     XORs <paramref name="source" /> with the keystream.
	/// </summary>
	/// <remarks>
	///     Each byte is folded three times: XOR with the constant <c>0xAB</c>, nibble swap, then XOR
	///     against both halves of the table indexed by the running position. Source and destination may
	///     be the same span, because every step reads the source byte before overwriting the
	///     destination byte and the position is tracked separately.
	/// </remarks>
	private static void Transform(Span<byte> source, Span<byte> destination, byte[] key, ref ushort counter)
	{
		if (destination.Length < source.Length)
		{
			throw new ArgumentException("Destination is shorter than source.", nameof(destination));
		}

		// The position is taken from the counter before it advances, then walked byte by byte. Starting
		// from the pre-advance value is what matches the client's own key schedule.
		ushort position = counter;
		counter = (ushort)(counter + source.Length);

		for (int i = 0; i < source.Length; i++)
		{
			byte value = (byte)(source[i] ^ 0xAB);

			value = (byte)((value >> 4) | (value << 4));
			value ^= key[position & 0xFF];
			value ^= key[(position >> 8) + 0x100];

			destination[i] = value;
			position++;
		}
	}

	private static byte[] BuildStaticTable()
	{
		byte[] table = new byte[TableSize];
		Span<byte> seed = stackalloc byte[8];

		StaticSeed.CopyTo(seed);

		for (int i = 0; i < 0x100; i++)
		{
			table[i] = seed[0];
			table[i + 0x100] = seed[4];

			// Two interleaved linear congruential recurrences. Every step is byte-truncated, which
			// is why the casts are explicit rather than left to integer promotion.
			seed[0] = (byte)((seed[1] + (seed[0] * seed[2])) * seed[0] + seed[3]);
			seed[4] = (byte)((seed[5] - (seed[4] * seed[6])) * seed[4] + seed[7]);
		}

		return table;
	}
}
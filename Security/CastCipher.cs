using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Myethos.Network.Security;

/// <summary>
///     CAST-128 in a byte-oriented cipher-feedback mode, the transport cipher of the game server
///     (port 5816) once the Diffie-Hellman exchange has run.
/// </summary>
/// <remarks>
///     <para>The mode is: keep an 8-byte register; every 8 bytes regenerate the keystream by
///     encrypting the register; each byte of the register is xored with the payload and then
///     <b>overwritten with the ciphertext</b> (CFB-8). Because both directions carry feedback, each
///     direction owns an independent register and counter.</para>
///     <para><b>Feedback is always the ciphertext.</b> For encryption that is the output, for
///     decryption it is the input. Folding the plaintext back into the register instead is the
///     classic way to build a stream nothing can decrypt, and it fails silently: the first block
///     decrypts correctly and everything after it is garbage.</para>
///     <para><b>Keystream direction.</b> Generation must always use the block cipher's
///     <i>encrypt</i> transform, in the decrypt path too. CAST-128's decrypt block is a
///     mathematically different transform, and using it here only shows up once the register wraps,
///     eight bytes at a time, at an offset that depends on how much traffic has already flowed.</para>
///     <para><b>Thread safety.</b> The engine is shared between both directions, so this type is
///     safe only when its owner serialises calls. A connection does: the receive loop owns decrypt and
///     the outbound pipeline admits one writer at a time.</para>
/// </remarks>
public sealed class CastCipher : INetworkCipher
{
	/// <summary>Width of the feedback register.</summary>
	public const int RegisterSize = 8;

	private const int RegisterMask = RegisterSize - 1;

	/// <summary>Static CAST-128 seed the game server uses before the key exchange completes.</summary>
	public const string DefaultSeed = "C238xs65pjy7HU9Q";

	/// <summary>Width of the CAST-128 key schedule.</summary>
	private const int KeySize = 16;

	private readonly Cast5Engine _engine = new();

	private byte[] _encryptRegister = new byte[RegisterSize];
	private byte[] _decryptRegister = new byte[RegisterSize];
	private int _encryptIndex;
	private int _decryptIndex;

	/// <summary>Creates a cipher keyed with the well-known static game seed.</summary>
	/// <param name="seed">ASCII seed, truncated to <see cref="KeySize" /> bytes.</param>
	public CastCipher(string seed = DefaultSeed)
	{
		ArgumentException.ThrowIfNullOrEmpty(seed);

		GenerateKeys(Encoding.ASCII.GetBytes(seed));
	}

	
	/// <remarks>
	///     Both registers and both indexes are adopted together or not at all. The client only ever
	///     supplies a full <c>[key, encryptIV, decryptIV]</c> triple, so a two-seed call means
	///     "no IVs" rather than "an encrypt IV and no decrypt IV": half a key schedule desynchronises
	///     the peer exactly as thoroughly as a wrong key does, and the symptom is identical.
	/// </remarks>
	public void GenerateKeys(params object[] seeds)
	{
		ArgumentNullException.ThrowIfNull(seeds);

		if (seeds.Length == 0 || seeds[0] is not byte[] keyBytes)
		{
			throw new ArgumentException(
				"CastCipher expects byte[] key material as the first seed.",
				nameof(seeds));
		}

		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyBytes.Length);

		byte[] key = new byte[KeySize];
		keyBytes.AsSpan(0, Math.Min(KeySize, keyBytes.Length)).CopyTo(key);

		_engine.Init(forEncryption: true, new KeyParameter(key));

		byte[]? encryptIv = null;
		byte[]? decryptIv = null;

		if (seeds.Length > 2)
		{
			encryptIv = seeds[1] as byte[];
			decryptIv = seeds[2] as byte[];
		}

		// Adopting the caller's IV arrays directly rather than copying them: they are freshly
		// deserialised per connection from the handshake frame and never touched again.
		_encryptRegister = Normalise(encryptIv);
		_decryptRegister = Normalise(decryptIv);
		_encryptIndex = 0;
		_decryptIndex = 0;
	}

	
	public void Encrypt(Span<byte> source, Span<byte> destination)
	{
		byte[] register = _encryptRegister;
		int index = _encryptIndex;

		ValidateLength(source, destination);

		for (int i = 0; i < source.Length; i++)
		{
			if (index == 0)
			{
				// Regenerate the keystream for the next register-sized block. Encrypt direction, even
				// though this is the encrypt path's own keystream.
				_engine.ProcessBlock(register, 0, register, 0);
			}

			byte cipherByte = (byte)(source[i] ^ register[index]);
			destination[i] = cipherByte;

			// Feedback is the ciphertext, which for encryption is the output.
			register[index] = cipherByte;
			index = (index + 1) & RegisterMask;
		}

		_encryptIndex = index;
	}

	
	public void Decrypt(Span<byte> source, Span<byte> destination)
	{
		byte[] register = _decryptRegister;
		int index = _decryptIndex;

		ValidateLength(source, destination);

		for (int i = 0; i < source.Length; i++)
		{
			if (index == 0)
			{
				_engine.ProcessBlock(register, 0, register, 0);
			}

			byte cipherByte = source[i];
			destination[i] = (byte)(register[index] ^ cipherByte);

			// Feedback is the ciphertext, which for decryption is the input.
			register[index] = cipherByte;
			index = (index + 1) & RegisterMask;
		}

		_decryptIndex = index;
	}

	private static byte[] Normalise(byte[]? iv)
	{
		if (iv is null || iv.Length < RegisterSize)
		{
			return new byte[RegisterSize];
		}

		if (iv.Length == RegisterSize)
		{
			return iv;
		}

		byte[] trimmed = new byte[RegisterSize];
		iv.AsSpan(0, RegisterSize).CopyTo(trimmed);
		return trimmed;
	}

	private static void ValidateLength(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (destination.Length < source.Length)
		{
			throw new ArgumentException("Destination is shorter than source.", nameof(destination));
		}
	}
}
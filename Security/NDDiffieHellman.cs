namespace Myethos.Network.Security;

/// <summary>
///     Non-standard Diffie-Hellman exchange used by the game server. Present in the client since the
///     50121 builds and unchanged through 6609.
/// </summary>
/// <remarks>
///     <para>
///         Both exponentiations are transposed relative to textbook DH, and BouncyCastle's
///         <see cref="BigInteger.ModPow" /> takes <c>(exponent, modulus)</c>, so the arguments read
///         "backwards" against normal expectations:
///     </para>
///     <list type="bullet">
///         <item><description>public key = <c>g ^ modulus mod primeRoot</c>;</description></item>
///         <item><description>shared secret = <c>clientKey ^ modulus mod primeRoot</c>.</description></item>
///     </list>
///     <para>
///         The generator is the constant 5, the "prime root" is a fixed 256-bit value, and the modulus
///         is a fresh 256-bit probable prime generated per connection. Both sides use the same prime
///         root as the <i>modulus</i>, which is what makes this exchange insecure and
///         non-interoperable with anything but the stock client. Getting either pair of arguments
///         swapped still "works" locally, so the only symptom is a client that stalls right after the
///         handshake; validate against a real 6609 client before touching any of it.
///     </para>
/// </remarks>
public sealed class NDDiffieHellman
{
	private const string DefaultGenerator = "05";

	private const string DefaultPrimeRoot =
		"E7A69EBDF105F2A6BBDEAD7E798F76A209AD73FB466431E2E7352ED262F8C558" +
		"F10BEFEA977DE9E21DCEE9B04D245F300ECCBBA03E72630556D011023F9E857F";

	private const int IvSize = 8;

	private static ReadOnlySpan<byte> HexAlphabet => "0123456789abcdef"u8;

	private readonly BigInteger _generator;
	private readonly BigInteger _primeRoot;

	private BigInteger? _modulus;
	private BigInteger? _publicKey;
	private BigInteger? _sharedSecret;

	/// <summary>Creates an exchange bound to the client's fixed prime root and generator.</summary>
	public NDDiffieHellman(string primeRoot = DefaultPrimeRoot, string generator = DefaultGenerator)
	{
		ArgumentException.ThrowIfNullOrEmpty(primeRoot);
		ArgumentException.ThrowIfNullOrEmpty(generator);

		_primeRoot = new BigInteger(primeRoot, 16);
		_generator = new BigInteger(generator, 16);

		EncryptionIV = new byte[IvSize];
		DecryptionIV = new byte[IvSize];
	}

	/// <summary>The fixed 256-bit value the client uses as the modulus of both exponentiations.</summary>
	public BigInteger PrimeRoot => _primeRoot;

	/// <summary>The fixed generator, 5.</summary>
	public BigInteger Generator => _generator;

	/// <summary>Per-connection 256-bit probable prime.</summary>
	/// <exception cref="InvalidOperationException">No modulus has been supplied yet.</exception>
	public BigInteger Modulus => _modulus ?? throw new InvalidOperationException("Modulus has not been supplied yet.");

	/// <summary>Server public key sent to the client.</summary>
	/// <exception cref="InvalidOperationException"><see cref="ComputePublicKey" /> has not run.</exception>
	public BigInteger PublicKey => _publicKey ?? throw new InvalidOperationException("Public key has not been computed yet.");

	/// <summary>Shared secret, available once <see cref="ComputeSharedSecret" /> has run.</summary>
	/// <exception cref="InvalidOperationException"><see cref="ComputeSharedSecret" /> has not run.</exception>
	public BigInteger SharedSecret => _sharedSecret ?? throw new InvalidOperationException("Shared secret has not been computed yet.");

	/// <summary>
	///     Eight bytes for the server's CAST-128 receive register. These start zeroed because the
	///     client sends its own pair inside the handshake and the session overwrites them with the
	///     values off the wire; randomising them here would silently desynchronise any caller that
	///     does not overwrite them.
	/// </summary>
	public byte[] EncryptionIV { get; set; }

	/// <summary>Eight bytes for the server's CAST-128 send register. See <see cref="EncryptionIV" />.</summary>
	public byte[] DecryptionIV { get; set; }

	/// <summary>Derives the public key from a supplied probable prime.</summary>
	public void ComputePublicKey(BigInteger modulus)
	{
		ArgumentNullException.ThrowIfNull(modulus);

		_modulus = modulus;

		// g ^ modulus mod primeRoot. The arguments are transposed on purpose; see the remarks.
		_publicKey = _generator.ModPow(modulus, _primeRoot);
	}

	/// <summary>Derives the shared secret from the client's public key, sent as ASCII hex.</summary>
	/// <param name="clientPublicKeyHex">The client's public key as lowercase hex.</param>
	/// <exception cref="ArgumentException">The key is empty.</exception>
	/// <exception cref="FormatException">The key is not valid hexadecimal.</exception>
	/// <exception cref="InvalidOperationException"><see cref="ComputePublicKey" /> has not run.</exception>
	public void ComputeSharedSecret(string clientPublicKeyHex)
	{
		ArgumentException.ThrowIfNullOrEmpty(clientPublicKeyHex);

		BigInteger modulus = _modulus ??
			throw new InvalidOperationException("ComputePublicKey must run before ComputeSharedSecret.");

		BigInteger clientKey = new(clientPublicKeyHex, 16);

		// clientKey ^ modulus mod primeRoot. Also transposed, and for the same reason.
		_sharedSecret = clientKey.ModPow(modulus, _primeRoot);
	}

	/// <summary>
	///     Turns the shared secret into the 64-character ASCII key material the client derives CAST-128
	///     from; the cipher key is the first 16 of those characters.
	/// </summary>
	/// <remarks>
	///     The first digest stops at the first zero byte of the big-endian secret. The client trims the
	///     same way, so "fixing" this by hashing the whole array shifts the entire keystream and the
	///     result still looks like a valid hash, which is what makes it easy to break by accident.
	///     <para>
	///         The hex is lowercase, which matters: these characters are hashed and then used as key
	///         material verbatim, so uppercase yields a well-formed but entirely different key.
	///     </para>
	/// </remarks>
	/// <exception cref="InvalidOperationException"><see cref="ComputeSharedSecret" /> has not run.</exception>
	public byte[] DeriveCipherKey()
	{
		byte[] secret = SharedSecret.ToByteArrayUnsigned();

		int significant = 0;
		while (significant < secret.Length && secret[significant] != 0)
		{
			significant++;
		}

		// MD5 is fixed by the 6609 client handshake, not chosen here. It is not a security decision.
#pragma warning disable CA5351
		string first = ToHex(MD5.HashData(secret.AsSpan(0, significant)));
		string second = ToHex(MD5.HashData(Encoding.ASCII.GetBytes(string.Concat(first, first))));
#pragma warning restore CA5351

		return Encoding.ASCII.GetBytes(string.Concat(first, second));
	}

	/// <summary>Renders bytes as lowercase ASCII hex, byte by byte, exactly as the client does.</summary>
	public static string ToHex(ReadOnlySpan<byte> bytes)
	{
		return string.Create(bytes.Length * 2, bytes.ToArray(), static (chars, source) =>
		{
			for (int i = 0; i < source.Length; i++)
			{
				chars[i * 2] = (char)HexAlphabet[source[i] >> 4];
				chars[(i * 2) + 1] = (char)HexAlphabet[source[i] & 0x0F];
			}
		});
	}

	/// <summary>Renders a non-negative integer as lowercase big-endian hex.</summary>
	public static string ToHex(BigInteger value) => ToHex(value.ToByteArrayUnsigned());
}
namespace Myethos.Network.Security;

/// <summary>
///     Background producer of 256-bit probable primes for <see cref="NDDiffieHellman" />.
/// </summary>
/// <remarks>
///     Each prime takes a few hundred candidate rounds of Miller-Rabin, which is far too slow to run
///     inline on the accept path: a burst of connections would stall every receive loop queued behind
///     it. Primes are therefore produced ahead of time into a bounded queue and consumed in constant
///     time.
/// </remarks>
public sealed class PrimeGeneratorService : IAsyncDisposable
{
	/// <summary>Bit length of the generated moduli; the client hard-codes 256.</summary>
	public const int ModulusBitLength = 256;

	/// <summary>Primes buffered ahead of demand.</summary>
	public const int DefaultQueueCapacity = 64;

	private readonly Channel<BigInteger> _primes;
	private readonly CancellationTokenSource _shutdown = new();
	private readonly Task _worker;

	/// <summary>Starts the producer loop.</summary>
	/// <param name="queueCapacity">Primes to buffer ahead of demand.</param>
	public PrimeGeneratorService(int queueCapacity = DefaultQueueCapacity)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queueCapacity);

		_primes = Channel.CreateBounded<BigInteger>(new BoundedChannelOptions(queueCapacity)
		{
			SingleReader = false,
			SingleWriter = true,
			AllowSynchronousContinuations = false,
			FullMode = BoundedChannelFullMode.Wait
		});

		_worker = Task.Run(ProduceAsync, CancellationToken.None);
	}

	/// <summary>Number of primes currently waiting to be handed to a connection.</summary>
	public int Pending => _primes.Reader.Count;

	/// <summary>Takes the next probable prime, waiting only if the pipeline is momentarily empty.</summary>
	/// <param name="cancellationToken">Cancels the wait.</param>
	/// <exception cref="ObjectDisposedException">The service is shutting down.</exception>
	public async ValueTask<BigInteger> NextAsync(CancellationToken cancellationToken = default)
	{
		using CancellationTokenSource linked =
			CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token, cancellationToken);

		try
		{
			return await _primes.Reader.ReadAsync(linked.Token).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw new ObjectDisposedException(nameof(PrimeGeneratorService));
		}
	}

	private async Task ProduceAsync()
	{
		while (!_shutdown.IsCancellationRequested)
		{
			BigInteger prime = GenerateProbablePrime();

			try
			{
				await _primes.Writer.WriteAsync(prime, _shutdown.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				return;
			}
		}
	}

	private static BigInteger GenerateProbablePrime()
	{
		Span<byte> buffer = stackalloc byte[ModulusBitLength / 8];

		while (true)
		{
			RandomNumberGenerator.Fill(buffer);

			// Big-endian unsigned magnitude. `new BigInteger(byte[])` would read these little-endian as
			// two's complement and hand back a negative number, which no ModPow accepts and which reports
			// one bit short. Setting the top two bits fixes the width at exactly 256, and the low bit is
			// forced so an even candidate is not thrown away by the primality test.
			buffer[0] |= 0xC0;
			buffer[^1] |= 0x01;

			BigInteger candidate = new(1, buffer.ToArray());

			if (candidate.IsProbablePrime(20))
			{
				return candidate;
			}
		}
	}

	
	public async ValueTask DisposeAsync()
	{
		await _shutdown.CancelAsync().ConfigureAwait(false);
		_primes.Writer.TryComplete();

		try
		{
			await _worker.ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
		}

		_shutdown.Dispose();
	}
}
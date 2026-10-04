namespace Myethos.Network.Communication;

/// <summary>Lifecycle position of a <see cref="ClientConnection" />.</summary>
public enum ConnectionStage
{
	/// <summary>Socket accepted, buffers rented, connection registered.</summary>
	Connected,

	/// <summary>The session handshake request has been queued.</summary>
	Handshaking,

	/// <summary>Reading and decrypting bytes, waiting for enough to decode a frame.</summary>
	Receiving,

	/// <summary>Decoding the Diffie-Hellman exchange frame.</summary>
	Exchanging,

	/// <summary>Authenticated, exchanging ordinary game frames.</summary>
	Established,

	/// <summary>Teardown requested; the receive loop is unwinding.</summary>
	Disconnecting,

	/// <summary>Torn down: socket closed, queues completed, buffers returned.</summary>
	Closed
}
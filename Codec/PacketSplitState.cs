namespace Myethos.Network.Codec;

/// <summary>Outcome of attempting to cut one frame out of a partially filled receive buffer.</summary>
public enum PacketSplitState
{
	/// <summary>Not enough bytes buffered yet; retry after the next receive.</summary>
	NeedMore,

	/// <summary>A full frame is present and <c>consumed</c> bytes may be retired.</summary>
	Complete,

	/// <summary>The bytes cannot be a frame. The connection must be terminated.</summary>
	Invalid
}
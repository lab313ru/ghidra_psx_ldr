package psyq;

public class MaskedBytes {

	private final byte[] bytes, masks;

	public final byte[] getBytes() {
		return bytes;
	}

	public final byte[] getMasks() {
		return masks;
	}
	
	public final int getLength() {
		return bytes.length;
	}

	public MaskedBytes(byte[] bytes, byte[] masks) {
		this.bytes = bytes;
		this.masks = masks;
	}
}

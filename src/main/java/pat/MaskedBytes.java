package pat;

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
	
	public static MaskedBytes extend(MaskedBytes src, MaskedBytes add) {
		return extend(src, add.getBytes(), add.getMasks());
	}
	
	public static MaskedBytes extend(MaskedBytes src, byte[] addBytes, byte[] addMasks) {
		int length = src.getBytes().length;
		
		byte[] tmpBytes = new byte[length + addBytes.length];
		byte[] tmpMasks = new byte[length + addMasks.length];
		
		System.arraycopy(src.getBytes(), 0, tmpBytes, 0, length);
		System.arraycopy(addBytes, 0, tmpBytes, length, addBytes.length);
		
		System.arraycopy(src.getMasks(), 0, tmpMasks, 0, length);
		System.arraycopy(addMasks, 0, tmpMasks, length, addMasks.length);
		
		return new MaskedBytes(tmpBytes, tmpMasks);
	}
}

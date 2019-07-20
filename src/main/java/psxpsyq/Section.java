package psxpsyq;

public final class Section extends Symbol {
	private final int group;
	private final byte alignment;
	private byte[] bytes;
	private int patchOffset;
	
	public Section(int number, String name, int group, byte alignment) {
		super(number, name, 0, 0);
		this.group = group;
		this.alignment = alignment;
		this.bytes = null;
		patchOffset = 0;
	}
	
	public byte[] getBytes() {
		return bytes;
	}
	
	@Override
	public long getLength() {
		return bytes != null ? bytes.length : 0;
	}
	
	public void setBytes(byte[] bytes) {
		patchOffset = this.bytes != null ? this.bytes.length : 0;
		this.bytes = bytes;
		
	}
	
	public void doAlign() {
		if ((bytes.length % alignment) != 0) {
			byte[] newBytes = new byte[bytes.length + (alignment - (bytes.length % alignment))];
			System.arraycopy(bytes, 0, newBytes, 0, bytes.length);
			this.bytes = newBytes;
		}
	}
	
	public int getPatchOffset() {
		return patchOffset;
	}

	public final int getGroup() {
		return group;
	}

	public final byte getAlignment() {
		return alignment;
	}
	
	public static final int importsSectionIndex = 0x0000;
	public static final String importsSectionName = ".imps";
}

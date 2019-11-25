package psyq.sym;

public class SymObject implements ISymObject {
	private long offset;
	private byte tag;
	
	protected SymObject(long offset, byte tag) {
		this.offset = offset;
		this.tag = tag;
	}

	@Override
	public long getOffset() {
		return offset;
	}

	@Override
	public byte getTag() {
		return tag;
	}

}

package psyq.sym;

public class SymObject implements ISymObject {
	private long offset;
	private int tag;
	
	protected SymObject(long offset, int tag) {
		this.offset = offset;
		this.tag = tag;
	}

	@Override
	public long getOffset() {
		return offset;
	}

	@Override
	public int getTag() {
		return tag;
	}

}

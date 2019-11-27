package psyq.sym;

public class SymObject implements ISymObject {
	protected long offset;
	private int tag;
	
	protected SymObject(long offset, int tag) {
		this.offset = offset;
		this.tag = tag;
	}

	@Override
	public long getOffset() {
		return offset;
	}
	
	public void setTag(int tag) {
		this.tag = tag;
	}

	@Override
	public int getTag() {
		return tag;
	}

}

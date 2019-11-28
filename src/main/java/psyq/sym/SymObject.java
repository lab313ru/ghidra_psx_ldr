package psyq.sym;

public class SymObject implements ISymObject {
	protected final long offset;
	
	protected SymObject(long offset) {
		this.offset = offset;
	}

	@Override
	public long getOffset() {
		return offset;
	}
}

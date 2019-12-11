package psyq.sym;

public class SymObject implements ISymObject {
	protected final long offset;
	protected final long overlayId;
	
	protected SymObject(long offset, long overlayId) {
		this.offset = offset;
		this.overlayId = overlayId;
	}

	@Override
	public long getOffset() {
		return offset;
	}
	
	@Override
	public long getOverlayId() {
		return overlayId;
	}
}

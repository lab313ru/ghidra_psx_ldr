package psyq.sym;

public class SymOverlay {
	
	private final long offset;
	private final long id;
	private final long size;
	
	public SymOverlay(long offset, long id, long size) {
		this.offset = offset;
		this.id = id;
		this.size = size;
	}
	
	public long getOffset() {
		return offset;
	}

	public long getSize() {
		return size;
	}
	
	public long getId() {
		return id;
	}
	
	public static String getBlockName(long id) {
		return String.format("OVR%d", id);
	}
}

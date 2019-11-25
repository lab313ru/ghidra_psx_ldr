package psyq.structs;

public final class RepeatedData {
	private final PatchInfo patch;
	private final long count;
	private final int size;
	
	public RepeatedData(PatchInfo patch, long count, int size) {
		this.patch = patch;
		this.count = count;
		this.size = size;
	}

	public final PatchInfo getPatch() {
		return patch;
	}

	public final long getCount() {
		return count;
	}

	public final int getSize() {
		return size;
	}
}

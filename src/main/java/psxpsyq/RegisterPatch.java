package psxpsyq;

public final class RegisterPatch {
	private final int size;
	private final PatchInfo patch;
	private final int offset;
	
	public final int getSize() {
		return size;
	}

	public final PatchInfo getPatch() {
		return patch;
	}

	public final int getOffset() {
		return offset;
	}

	public RegisterPatch(int size, PatchInfo patch, int offset) {
		this.size = size;
		this.patch = patch;
		this.offset = offset;
	}
}

package psxpsyq;

public final class BlockStart {
	private final int section;
	private final long offset;
	private final long startLine;
	
	public final int getSection() {
		return section;
	}

	public final long getOffset() {
		return offset;
	}
	
	public final long getStartLine() {
		return startLine;
	}

	public BlockStart(int section, long offset, long startLine) {
		this.section = section;
		this.offset = offset;
		this.startLine = startLine;
	}
}

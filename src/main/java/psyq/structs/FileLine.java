package psyq.structs;

public final class FileLine {
	private final int fileIndex;
	private long lineIndex;

	public void setLineIndex(long lineIndex) {
		this.lineIndex = lineIndex;
	}
	
	public final int getFileIndex() {
		return fileIndex;
	}

	public long getLineIndex() {
		return lineIndex;
	}
	
	public FileLine() {
		this.fileIndex = 0;
		this.lineIndex = 0L;
	}

	public FileLine(int fileIndex, long lineIndex) {
		this.fileIndex = fileIndex;
		this.lineIndex = lineIndex;
	}
}

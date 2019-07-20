package psxpsyq;

import java.util.HashMap;

public final class SldFileLine {
	private final int fileIndex;
	private HashMap<Integer, Long> lines;
	
	public final int getFileIndex() {
		return fileIndex;
	}

	public HashMap<Integer, Long> getLines() {
		return lines;
	}
	
	public long getLineAtOffset(int offset) {
		return lines.getOrDefault(offset, 0L);
	}
	
	public void incLineAtOffset(int offset) {
		incLineAtOffsetByVal(offset, 1);
	}
	
	public void incLineAtOffsetByVal(int offset, long val) {
		long line = lines.getOrDefault(offset, 0L) + val;
		setLineAtOffset(offset, line);
	}
	
	public void setLineAtOffset(int offset, long line) {
		lines.put(offset, line);
	}
	
	public SldFileLine() {
		this.lines = new HashMap<>();
		this.fileIndex = 0;
	}
}

package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymSrcFile extends SymObject {
	private String file;
	private List<SymSld> lines = new ArrayList<>();
	
	private long startOffset;
	private long endOffset;
	
	public SymSrcFile(String file, long startOffset) {
		super(startOffset, (byte)0x88);
		
		this.file = file;
		this.startOffset = startOffset;
		this.endOffset = startOffset;
	}
	
	public void setFilePath(String file) {
		this.file = file;
	}
	
	public void setEndOffset(long endOffset) {
		this.endOffset = endOffset;
	}
	
	public String getFilePath() {
		return file;
	}
	
	public long getStartOffset() {
		return startOffset;
	}
	
	public long getEndOffset() {
		return endOffset;
	}
	
	public void addLine(SymSld line) {
		lines.add(line);
	}
	
	public SymSld[] getLines() {
		return lines.toArray(SymSld[]::new);
	}
}

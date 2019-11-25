package psyq.sym;

public class SymFuncBlock extends SymObject {
	long startLine;
	long startOffset;
	long endLine;
	long endOffset;
	
	public SymFuncBlock(long startLine, long startOffset) {
		super(startOffset, (byte)0x90);
		
		this.startLine = startLine;
		this.startOffset = startOffset;
		this.endLine = startLine;
		this.endOffset = startOffset;
	}

	public long getStartLine() {
		return startLine;
	}

	public long getStartOffset() {
		return startOffset;
	}
	
	public void setEndLineAndOffset(long endLine, long endOffset) {
		this.endLine = endLine;
		this.endOffset = endOffset;
	}

	public long getEndLine() {
		return endLine;
	}

	public long getEndOffset() {
		return endOffset;
	}
}

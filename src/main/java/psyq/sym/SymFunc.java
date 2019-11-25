package psyq.sym;

public class SymFunc extends SymObject {
	String fileName;
	String funcName;
	
	long startOffset;
	long endOffset;

	public SymFunc(String fileName, String funcName, long startOffset) {
		super(startOffset, (byte)0x8C);
		
		this.startOffset = startOffset;
		this.endOffset = startOffset;
		
		this.fileName = fileName;
		this.funcName = funcName;
	}
	
	public long getStartOffset() {
		return startOffset;
	}
	
	public void setEndOffset(long endOffset) {
		this.endOffset = endOffset;
	}
	
	public long getEndOffset() {
		return endOffset;
	}

	public String getFileName() {
		return fileName;
	}

	public String getFuncName() {
		return funcName;
	}
}

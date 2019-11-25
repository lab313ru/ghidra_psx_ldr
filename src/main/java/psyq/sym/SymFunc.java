package psyq.sym;

public class SymFunc extends SymObject {
	int fp;
	long fsize;
	int retreg;
	long mask;
	long maskoffs;
	long line;
	String fileName;
	String funcName;
	
	long startOffset;
	long endOffset;

	public SymFunc(int fp, long fsize, int retreg, long mask, long maskoffs, long line, String fileName, String funcName,
			long startOffset) {
		super(startOffset, (byte)0x8C);
		
		this.startOffset = startOffset;
		this.endOffset = startOffset;
		
		this.fp = fp;
		this.fsize = fsize;
		this.retreg = retreg;
		this.mask = mask;
		this.maskoffs = maskoffs;
		this.line = line;
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

	public int getFp() {
		return fp;
	}

	public long getFsize() {
		return fsize;
	}

	public int getRetreg() {
		return retreg;
	}

	public long getMask() {
		return mask;
	}

	public long getMaskoffs() {
		return maskoffs;
	}

	public long getLine() {
		return line;
	}

	public String getFileName() {
		return fileName;
	}

	public String getFuncName() {
		return funcName;
	}
}

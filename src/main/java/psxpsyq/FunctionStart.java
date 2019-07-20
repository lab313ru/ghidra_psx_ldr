package psxpsyq;

public final class FunctionStart {
	private final int section;
	private final long offset;
	private final int file;
	private final long startLine;
	private final int frameReg;
	private final long frameSize;
	private final int retnPcReg;
	private final long mask;
	private final long maskOffset;
	private final String name;
	
	public final int getSection() {
		return section;
	}

	public final long getOffset() {
		return offset;
	}

	public final int getFile() {
		return file;
	}

	public final long getStartLine() {
		return startLine;
	}

	public final int getFrameReg() {
		return frameReg;
	}

	public final long getFrameSize() {
		return frameSize;
	}

	public final int getRetnPcReg() {
		return retnPcReg;
	}

	public final long getMask() {
		return mask;
	}

	public final long getMaskOffset() {
		return maskOffset;
	}

	public final String getName() {
		return name;
	}

	public FunctionStart(int section, long offset, int file, long startLine, int frameReg, long frameSize, int retnPcReg,
			long mask, long maskOffset, String name) {
		this.section = section;
		this.offset = offset;
		this.file = file;
		this.startLine = startLine;
		this.frameReg = frameReg;
		this.frameSize = frameSize;
		this.retnPcReg = retnPcReg;
		this.mask = mask;
		this.maskOffset = maskOffset;
		this.name = name;
	}
}

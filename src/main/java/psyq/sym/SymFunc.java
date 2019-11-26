package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymFunc extends SymObject {
	String fileName;
	String funcName;
	
	long startOffset;
	long endOffset;
	
	List<SymDef> args = new ArrayList<>();

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
	
	public void addArgument(SymDef arg) {
		args.add(arg);
	}
	
	public SymDef[] getArguments() {
		return args.toArray(SymDef[]::new);
	}
}

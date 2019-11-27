package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymFunc extends SymObject {
	String fileName = null;
	String funcName = null;
	
	long endOffset = 0L;
	
	List<SymDef> args = new ArrayList<>();
	SymDefType retnType = null;
	

	public SymFunc(long offset, SymDefType retnType, String funcName) {
		super(offset, 0);
		
		this.retnType = retnType;
		this.funcName = funcName;
	}
	
	public void setEndOffset(long endOffset) {
		this.endOffset = endOffset;
	}
	
	public long getEndOffset() {
		return endOffset;
	}
	
	public void setFileName(String fileName) {
		this.fileName = fileName;
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
	
	public SymDefType getReturnType() {
		return retnType;
	}
}

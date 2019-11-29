package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymFunc extends SymObject {
	private String fileName = null;
	private final String funcName;
	
	private long endOffset = 0L;
	
	private final List<SymDef> args = new ArrayList<>();
	private final SymDef retnType;
	

	public SymFunc(long offset, SymDef retnType, String funcName) {
		super(offset);
		
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
	
	public SymDef getReturnType() {
		return retnType;
	}

	public String getReturnTypeAsString() {
		SymDefTypePrim[] primTypes = retnType.getDefType().getTypesList();
		StringBuilder builder = new StringBuilder();
		
		for (int i = 1; i < primTypes.length; ++i) {
			builder.append(primTypes[i].name()).append(' ');
		}
		
		return builder.toString();
	}
}

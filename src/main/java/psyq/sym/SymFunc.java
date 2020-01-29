package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymFunc extends SymName {
	private String fileName = null;
	
	private long endOffset = 0L;
	
	private final List<SymDef> args = new ArrayList<>();
	private final SymDef retnType;
	

	public SymFunc(SymDef retnType, String funcName, long offset, long overlayId) {
		super(funcName, offset, overlayId);
		
		this.retnType = retnType;
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
	
	public void addArgument(SymDef arg) {
		args.add(arg);
	}
	
	public SymDef[] getArguments() {
		return args.toArray(SymDef[]::new);
	}
	
	public SymDef getReturnType() {
		return retnType;
	}

//	public String getReturnTypeAsString() {
//		SymDefTypePrim[] primTypes = retnType.getDefType().getTypesList();
//		StringBuilder builder = new StringBuilder();
//		
//		for (int i = 1; i < primTypes.length; ++i) {
//			builder.append(primTypes[i].name()).append(' ');
//		}
//		
//		return builder.toString();
//	}
	
	public String getPrototype() {
		StringBuilder builder = new StringBuilder();
		SymDefTypePrim[] primTypes = retnType.getDefType().getTypesList();
		
		for (int i = 1; i < primTypes.length; ++i) {
			builder.append(primTypes[i].name()).append(' ');
		}
		
		builder.append('(');
		
		for (SymDef arg : args) {
			builder.append(arg.getName()).append(' ');
		}
		
		return builder.toString();
	}
}

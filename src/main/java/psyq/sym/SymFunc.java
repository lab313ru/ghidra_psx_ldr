package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymFunc extends SymName {
	private String fileName = null;
	
	private long endOffset = 0L;
	
	private final List<SymDefinition> args = new ArrayList<>();
	private final SymDefinition retnType;
	

	public SymFunc(SymDefinition retnType, String funcName, long offset, long overlayId) {
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
	
	public void addArgument(SymDefinition arg) {
		args.add(arg);
	}
	
	public SymDefinition[] getArguments() {
		return args.toArray(SymDefinition[]::new);
	}
	
	public SymDefinition getReturnType() {
		return retnType;
	}
	
	public String getPrototype() {
		StringBuilder builder = new StringBuilder();
		SymTypePrimitive[] primTypes = retnType.getSymType().getTypesList();
		
		for (int i = 1; i < primTypes.length; ++i) {
			builder.append(primTypes[i].name()).append(' ');
		}
		
		builder.append('(');
		
		for (SymDefinition arg : args) {
			builder.append(arg.getName()).append(' ');
		}
		
		return builder.toString();
	}
}

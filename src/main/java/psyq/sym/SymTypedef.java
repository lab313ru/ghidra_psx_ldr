package psyq.sym;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class SymTypedef extends SymObject {
	private final SymDef base;
	
	public SymTypedef(SymDef base) {
		super(0L, 0L);
		
		this.base = base;
	}
	
	public String getName() {
		return base.getName();
	}
	
	public DataType getDataType(DataTypeManager mgr) {
		return base.getDataType(mgr);
	}
}

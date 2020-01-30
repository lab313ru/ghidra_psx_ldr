package psyq.sym;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class SymTypedef extends SymName {
	private final SymDef base;
	
	public SymTypedef(SymDef base) {
		super(base.getName(), 0L, 0L);
		
		this.base = base;
	}
	
	@Override
	public String getName() {
		return base.getName();
	}
	
	@Override
	public void setName(String newName) {
		base.setName(newName);
	}
	
	public String getTag() {
		return base.getTag();
	}
	
	public DataType getBaseDataType(DataTypeManager mgr) {
		return base.getDataType(mgr);
	}
}

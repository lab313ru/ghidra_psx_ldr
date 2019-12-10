package psyq.sym;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class SymExtStat extends SymObject {

	private final SymDef def;
	
	public SymExtStat(long offset, SymDef def) {
		super(offset);
		
		this.def = def;
	}

	public String getName() {
		return def.getName();
	}
	
	public DataType getDataType(DataTypeManager mgr) {
		return def.getDataType(mgr);
	}
}

package psyq.sym;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class SymExtStat extends SymObject {

	private final SymDef def;
	
	public SymExtStat(SymDef def, long offset, long overlayId) {
		super(offset, overlayId);
		
		this.def = def;
	}

	public String getName() {
		return def.getName();
	}
	
	public DataType getDataType(DataTypeManager mgr) {
		return def.getDataType(mgr);
	}
}

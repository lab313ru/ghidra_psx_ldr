package psyq.sym;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class SymExtStat extends SymName {

	private final SymDef def;
	
	public SymExtStat(SymDef def, long offset, long overlayId) {
		super(def.getName(), offset, overlayId);
		
		this.def = def;
	}

	@Override
	public String getName() {
		return def.getName();
	}
	
	@Override
	public void setName(String newName) {
		def.setName(newName);
	}
	
	public DataType getDataType(DataTypeManager mgr) {
		return def.getDataType(mgr);
	}
}

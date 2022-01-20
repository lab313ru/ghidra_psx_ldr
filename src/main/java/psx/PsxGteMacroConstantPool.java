package psx;

import java.util.List;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class PsxGteMacroConstantPool extends ConstantPool {

	private Program program;
	private Listing listing;
	private SymbolTable symTable;
	
	public PsxGteMacroConstantPool(Program program) {
		this.program = program;
		this.listing = program.getListing();
		this.symTable = program.getSymbolTable();
	}
	
	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		
		long address = ref[1];
		AddressSpace defSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		switch ((int)ref[0]) {
		case 0:
			Instruction instr = listing.getInstructionAt(defSpace.getAddress(address));
			String mnemonic = instr.getMnemonicString();
			
			List<Symbol> funcs = symTable.getLabelOrFunctionSymbols(String.format("gte_%s", mnemonic), null);
			
			if (funcs.size() == 0) {
				return null;
			}
			
			long funcAddr = funcs.get(0).getAddress().getOffset();
			
			res.type = LongDataType.dataType;
			res.value = funcAddr;
			res.token = "long";
			
			return res;
		}
		
		return null;
	}

}

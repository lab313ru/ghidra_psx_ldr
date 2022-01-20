package psx;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;

public class PsxGteMacroInjectLibrary extends PcodeInjectLibrary {

	public PsxGteMacroInjectLibrary(SleighLanguage l) {
		super(l);
	}

	public PsxGteMacroInjectLibrary(PsxGteMacroInjectLibrary op2) {
		super(op2);
	}
	
	@Override
	public PcodeInjectLibrary clone() {
		return new PsxGteMacroInjectLibrary(this);
	}
	
	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new PsxGteMacroConstantPool(program);
	}
}

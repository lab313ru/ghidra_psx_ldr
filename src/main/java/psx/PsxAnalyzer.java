package psx;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.feature.fid.cmd.ApplyFidEntriesCommand;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;


public class PsxAnalyzer extends AbstractAnalyzer {
	private static boolean isPsxLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(PsxLoader.PSX_LOADER);
	}
	
	public PsxAnalyzer() {
		super("PsyQ Signatures", "PSX signatures applier", AnalyzerType.INSTRUCTION_ANALYZER);
	}
	
	@Override
	public boolean getDefaultEnablement(Program program) {
		return isPsxLoader(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isPsxLoader(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		ApplyFidEntriesCommand cmd = new ApplyFidEntriesCommand(set, 3.0f, 30.0f, true, true);
		cmd.applyTo(program);
		
		return true;
	}
}

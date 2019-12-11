package psx;

import java.io.File;
import java.io.IOException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import pat.PatParser;
import psyq.DetectPsyQ;


public class PsxAnalyzer extends AbstractAnalyzer {
	private static PatParser pat = null;
	
	public static boolean isPsxLoader(Program program) {
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
		Memory mem = program.getMemory();
		
		try {
			String psyVersion = DetectPsyQ.getPsyqVersion(mem, program.getAddressFactory().getDefaultAddressSpace().getAddress(PsxLoader.ramBase));
			
			if (psyVersion == null) {
				return false;
			}
			
			File patFile = Application.getModuleDataFile(String.format("psyq%s.pat", psyVersion)).getFile(false);
			if (pat == null) {
				pat = new PatParser(patFile, monitor);
			}
			
			AddressRangeIterator i = set.getAddressRanges();
			
			while (i.hasNext()) {
				AddressRange next = i.next();
				
				pat.applySignatures(program, next.getMinAddress(), next.getMaxAddress(), log);
			}
		} catch (MemoryAccessException | AddressOutOfBoundsException | IOException e) {
			log.appendException(e);
			return false;
		}
		
		return true;
	}
}

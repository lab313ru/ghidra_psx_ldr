package psx;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import pat.PatParser;


public class PsxAnalyzer extends AbstractAnalyzer {
	private Map<String, PatParser> parsers = new HashMap<>();
	
	public static boolean isPsxLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(PsxLoader.PSX_LOADER);
	}
	
	public PsxAnalyzer() {
		super("PsyQ Signatures", "PSX signatures applier", AnalyzerType.INSTRUCTION_ANALYZER);
		
		setSupportsOneTimeAnalysis();
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
		try {
			String psyqVersion = PsxLoader.getProgramPsyqVersion(program);
			
			if (psyqVersion.isEmpty()) {
				return false;
			}
			
			PatParser pat;
			if (parsers.containsKey(psyqVersion)) {
				pat = parsers.get(psyqVersion);
			} else {
				File patFile = Application.getModuleDataFile(String.format("psyq%s.pat", psyqVersion)).getFile(false);
				pat = new PatParser(patFile, monitor);
				
				parsers.put(psyqVersion, pat);
			}
			
			AddressRangeIterator i = set.getAddressRanges();
			
			while (i.hasNext()) {
				AddressRange next = i.next();
				
				pat.applySignatures(program, next.getMinAddress(), next.getMaxAddress(), monitor, log);
			}
			
			monitor.setMessage("Applying PsyQ functions and data types...");
			monitor.clearCanceled();
			
			PsxLoader.loadPsyqGdt(program, set);
			
			monitor.setMessage("Applying PsyQ functions and data types done.");
		} catch (IOException e) {
			log.appendException(e);
			return false;
		}
		
		return true;
	}
}

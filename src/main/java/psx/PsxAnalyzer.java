package psx;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import pat.PatParser;
import psyq.DetectPsyQ;


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
		Memory mem = program.getMemory();
		
		try {
			String psyVersion = DetectPsyQ.getPsyqVersion(mem, program.getAddressFactory().getDefaultAddressSpace().getAddress(PsxLoader.ramBase));
			
			if (psyVersion == null) {
				return false;
			}
			
			PatParser pat;
			if (parsers.containsKey(psyVersion)) {
				pat = parsers.get(psyVersion);
			} else {
				File patFile = Application.getModuleDataFile(String.format("psyq%s.pat", psyVersion)).getFile(false);
				pat = new PatParser(patFile, monitor);
				
				parsers.put(psyVersion, pat);
			}
			
			AddressRangeIterator i = set.getAddressRanges();
			
			while (i.hasNext()) {
				AddressRange next = i.next();
				
				pat.applySignatures(program, next.getMinAddress(), next.getMaxAddress(), monitor, log);
			}
			
			monitor.setMessage("Applying PsyQ functions and data types...");
			monitor.clearCanceled();

			String gdtName = String.format("psyq%s", psyVersion);
			
			DataTypeManagerService srv = AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();
			closePsyqDataTypeArchives(srv, gdtName);
			
			DataTypeManager mgrPsyq = srv.openDataTypeArchive(gdtName);
			
			if (mgrPsyq != null) {
				applyDataTypes(program, set, mgrPsyq, monitor);
			}
			
			monitor.setMessage("Applying PsyQ functions and data types done.");
		} catch (MemoryAccessException | AddressOutOfBoundsException | IOException e) {
			log.appendException(e);
			return false;
		} catch (DuplicateIdException e) {
			return true;
		}
		
		return true;
	}
	
	public static void closePsyqDataTypeArchives(DataTypeManagerService srv, String currArch) {
		DataTypeManager[] mgrs = srv.getDataTypeManagers();

		for (DataTypeManager mgr : mgrs) {
			if (!mgr.getName().contains(currArch)) {
				srv.closeArchive(mgr);
			}
		}
	}
	
	private static void applyDataTypes(Program program, AddressSetView set, DataTypeManager mgr, TaskMonitor monitor) {
		List<DataTypeManager> gdtList = new ArrayList<>();
		gdtList.add(mgr);
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(gdtList, set, SourceType.ANALYSIS, true, false);
		cmd.applyTo(program, monitor);
	}
}

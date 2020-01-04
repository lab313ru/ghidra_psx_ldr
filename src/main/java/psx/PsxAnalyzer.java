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
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
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

			String gdtName = String.format("psyq%s", psyqVersion);
			
			closePsyqDataTypeArchives(program, gdtName);
			
			DataTypeManagerService srv = AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();
			DataTypeManager mgrPsyq = srv.openDataTypeArchive(gdtName);
			
			if (mgrPsyq != null) {
				applyDataTypes(program, set, mgrPsyq, monitor);
			}
			
			monitor.setMessage("Applying PsyQ functions and data types done.");
		} catch (IOException e) {
			log.appendException(e);
			return false;
		} catch (DuplicateIdException e) {
			return true;
		}
		
		return true;
	}
	
	public static void closePsyqDataTypeArchives(Program program, String currVer) {
		DataTypeManagerService srv = AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();
		DataTypeManager[] mgrs = srv.getDataTypeManagers();

		for (DataTypeManager mgr : mgrs) {
			if (!mgr.getName().contains(currVer)) {
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

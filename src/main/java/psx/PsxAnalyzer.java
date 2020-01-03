package psx;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import pat.PatParser;
import psyq.DetectPsyQ;


public class PsxAnalyzer extends AbstractAnalyzer {
	private static PatParser pat = null;
	private Archive gdt = null;
	private static String psyVersion = null;
	
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
			if (psyVersion == null) {
				psyVersion = DetectPsyQ.getPsyqVersion(mem, program.getAddressFactory().getDefaultAddressSpace().getAddress(PsxLoader.ramBase));
			}
			
			if (psyVersion == null) {
				return false;
			}
			
			if (pat == null) {
				File patFile = Application.getModuleDataFile(String.format("psyq%s.pat", psyVersion)).getFile(false);
				pat = new PatParser(patFile, monitor);
			}
			
			AddressRangeIterator i = set.getAddressRanges();
			
			while (i.hasNext()) {
				AddressRange next = i.next();
				
				pat.applySignatures(program, next.getMinAddress(), next.getMaxAddress(), log);
			}

			DataTypeManagerPlugin mgr = PsxPlugin.getDataTypeManagerPlugin();
			
			if (mgr == null) {
				return true;
			}
			
			String gdtName = String.format("psyq%s", psyVersion);
			DataTypeManager[] arches = mgr.getDataTypeManagers();
			
			for (DataTypeManager dtm : arches) {
				if (dtm.getName().equals("generic_clib")) {
					mgr.closeArchive(dtm);
					break;
				}
			}
			
			for (DataTypeManager dtm : arches) {
				if (dtm.getName().equals(gdtName)) {
					applyDataTypes(program, set, dtm);
					return true;
				}
			}
			
			if (gdt == null) {
				gdt = mgr.openArchive(Application.getModuleDataFile(String.format("%s.%s", gdtName, FileDataTypeManager.EXTENSION)).getFile(false), false);
			}

			applyDataTypes(program, set, gdt.getDataTypeManager());
		} catch (MemoryAccessException | AddressOutOfBoundsException | IOException e) {
			log.appendException(e);
			return false;
		} catch (DuplicateIdException e) {
			return true;
		}
		
		return true;
	}
	
	private static void applyDataTypes(Program program, AddressSetView set, DataTypeManager mgr) {
		List<DataTypeManager> gdtList = new ArrayList<>();
		gdtList.add(mgr);
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(gdtList, set, SourceType.ANALYSIS, true, false);
		cmd.applyTo(program);
	}
}

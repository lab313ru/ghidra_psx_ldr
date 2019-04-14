package psx;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import pat.PatParser;


public class PsxAnalyzer extends AbstractAnalyzer {

	private static final String OPTION_NAME = "PSYQ PAT-File Path";
	private File file = null;
	
	public static boolean isPsxLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(PsxLoader.PSX_LOADER);
	}
	
	public PsxAnalyzer() {
		super("PSYQ Signatures", "PSX signatures applier", AnalyzerType.INSTRUCTION_ANALYZER);
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
	public void registerOptions(Options options, Program program) {
		try {
			file = Application.getModuleDataFile("psyq4_7.pat").getFile(false);
		} catch (FileNotFoundException e) {
			
		}
		options.registerOption(OPTION_NAME, OptionType.FILE_TYPE, file, null,
				"PAT-File (FLAIR) created from PSYQ library files");
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		
		file = options.getFile(OPTION_NAME, file);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		if (file == null) {
			return true;
		}

		Memory memory = program.getMemory();
		AddressRangeIterator it = memory.getLoadedAndInitializedAddressSet().getAddressRanges();
		while (!monitor.isCancelled() && it.hasNext()) {
			AddressRange range = it.next();

			try {
				MemoryBlock block = program.getMemory().getBlock(range.getMinAddress());
				if (block.isInitialized() && block.isExecute() && block.isLoaded()) {
					PatParser pat = new PatParser(file, monitor);
					RandomAccessByteProvider provider = new RandomAccessByteProvider(new File(program.getExecutablePath()));
					
					pat.applySignatures(provider, program, block.getStart(), block.getStart(), block.getEnd(), log);
				}
			} catch (IOException e) {
				log.appendException(e);
				return false;
			}
		}
		return true;
	}
}

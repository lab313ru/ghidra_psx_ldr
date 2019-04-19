package psx;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import pat.PatParser;


public class PsxAnalyzer extends AbstractAnalyzer {

	private static final String OPTION_NAME = "PSYQ PAT-File Path";
	private File file = null;

    private boolean analyzed = false;

	private static final byte[] MAIN_SIGN = new byte[]{
			0x00, 0x00, 0x00, 0x0C,
			0x00, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x00, 0x00
	};

	private static final byte[] MAIN_SIGN_MASK = new byte[]{
			0x00, 0x00, 0x00, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF
	};
	
	private static boolean isPsxLoader(Program program) {
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
		} catch (FileNotFoundException ignored) {
			
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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		
		if (file == null || analyzed) {
			return false;
		}

        PatParser pat;
        try {
			pat = new PatParser(file, monitor);
		} catch (IOException e) {
			return false;
		}
		
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		
		MemoryBlock codeBlock = program.getMemory().getBlock(PsxExe.CODE_SEGM);
		for (MemoryBlock block : blocks) {
			if (block.isMapped() || !block.getName().equals(PsxExe.CODE_SEGM)) {
				continue;
			}
			codeBlock = block;
		}

		pat.applySignatures(program, codeBlock.getStart(), codeBlock.getEnd(), log);
		findAndAppyMain(program, codeBlock.getStart(), log);
		
		analyzed = true;
		
		return true;
	}
	
	private void findAndAppyMain(Program program, Address searchAddress, MessageLog log) {
		Address mainRefAddr = program.getMemory().findBytes(searchAddress, MAIN_SIGN, MAIN_SIGN_MASK, true, TaskMonitor.DUMMY);
		
		if (mainRefAddr != null) {
			Instruction instr = program.getListing().getInstructionAt(mainRefAddr);
			
			if (instr == null) {
				return;
			}
			
			Reference[] refs = instr.getReferencesFrom();
			
			if (refs.length == 0) {
				return;
			}
			
			try {
				program.getSymbolTable().createLabel(refs[0].getToAddress(), "main", SourceType.USER_DEFINED);
			} catch (InvalidInputException e) {
				log.appendException(e);
			}
		}
	}
}

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package psx;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import pat.PatParser;

public class PsxLoader extends AbstractLibrarySupportLoader {
	
	private static final long RAM_START_B = 0x80000000L;
	private static final long RAM_SIZE = 0x200000L;
	
	public static final String PSX_LOADER = "PSX Executables Loader";
	
	private PsxExe psxExe;

	@Override
	public String getName() {
		return PSX_LOADER;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		
		psxExe = new PsxExe(reader);
		
		if (psxExe.isParsed()) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log)
			throws IOException {

		if (!psxExe.isParsed()) {
			monitor.setMessage(String.format("%s : Cannot load", getName()));
			return;
		}
		
		monitor.setMessage(String.format("%s : Start loading", getName()));
		
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);
		
		createSegments(provider, program, fpa, log);
		
		PatParser.setFunction(program, fpa, fpa.toAddr(psxExe.getInitPc()), "start", true, true, log);

		setRegisterValue(program, fpa, "gp", psxExe.getInitPc(), psxExe.getInitGp(), log);
		setRegisterValue(program, fpa, "sp", psxExe.getInitPc(), psxExe.getSpBase() + psxExe.getSpOff(), log);
		
		monitor.setMessage(String.format("%s : Loading done", getName()));
	}
	
	private static void setRegisterValue(Program program, FlatProgramAPI fpa, String name, long startAddress, long value, MessageLog log) {
		RegisterValue regVal = new RegisterValue(program.getRegister(name), BigInteger.valueOf(value));
		Address start = fpa.toAddr(startAddress);
		try {
			program.getProgramContext().setRegisterValue(start, start, regVal);
		} catch (ContextChangeException e) {
			log.appendException(e);
		}
	}
	
	private void createSegments(ByteProvider provider, Program program, FlatProgramAPI fpa, MessageLog log) throws IOException {
		InputStream codeStream = provider.getInputStream(PsxExe.HEADER_SIZE);
		
		long ram_b_size_1 = psxExe.getRomStart() - RAM_START_B;
		createSegment(fpa, null, "RAM", RAM_START_B, ram_b_size_1, false, true, log);
		
		long code_b_size = psxExe.getRomSize();
		long code_addr_b = psxExe.getRomStart();
		createSegment(fpa, codeStream, "CODE", code_addr_b, code_b_size, false, true, log);
		
		if (psxExe.getDataAddr() != 0) {
			createSegment(fpa, null, "DATA", psxExe.getDataAddr(), psxExe.getDataSize(), false, true, log);
		}
		
		if (psxExe.getBssAddr() != 0) {
			createSegment(fpa, null, "BSS", psxExe.getBssAddr(), psxExe.getBssSize(), false, true, log);
		}
		
		long code_end = psxExe.getRomEnd();
		long ram_b_size_2 = RAM_START_B + RAM_SIZE - code_end;
		createSegment(fpa, null, "RAM", code_end, ram_b_size_2, false, true, log);
		
		createSegment(fpa, null, "CACHE", 0x1F800000L, 0x400, true, true, log);
		createSegment(fpa, null, "UNK1", 0x1F800400L, 0xC00, true, true, log);
		
		addMemCtrl1(fpa, program, log);
		addMemCtrl2(fpa, program, log);
		addPeriphIo(fpa, program, log);
		addIntCtrl(fpa, program, log);
		addDma(fpa, program, log);
		addTimers(fpa, program, log);
		addCdromRegs(fpa, program, log);
		addGpuRegs(fpa, program, log);
		addMdecRegs(fpa, program, log);
		addSpuVoices(fpa, program, log);
		addSpuCtrlRegs(fpa, program, log);
	}
	
	private void addMemCtrl1(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "MCTRL1", 0x1F801000L, 0x24, true, false, log);
		
		createNamedDword(fpa, program, 0x1F801000L, "EXP1_BASE_ADDR", log);
		createNamedDword(fpa, program, 0x1F801004L, "EXP2_BASE_ADDR", log);
		createNamedDword(fpa, program, 0x1F801008L, "EXP1_DELAY_SIZE", log);
		createNamedDword(fpa, program, 0x1F80100CL, "EXP3_DELAY_SIZE", log);
		createNamedDword(fpa, program, 0x1F801010L, "BIOS_ROM", log);
		createNamedDword(fpa, program, 0x1F801014L, "SPU_DELAY", log);
		createNamedDword(fpa, program, 0x1F801018L, "CDROM_DELAY", log);
		createNamedDword(fpa, program, 0x1F80101CL, "EXP2_DELAY_SIZE", log);
		createNamedDword(fpa, program, 0x1F801020L, "COMMON_DELAY", log);
	}
	
	private void addMemCtrl2(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "MCTRL2", 0x1F801060L, 4, true, false, log);
		
		createNamedDword(fpa, program, 0x1F801060L, "RAM_SIZE", log);
	}
	
	private void addPeriphIo(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "IO_PORTS", 0x1F801040L, 0x20, true, false, log);
		
		createNamedDword(fpa, program, 0x1F801040L, "JOY_MCD_DATA", log);
		createNamedDword(fpa, program, 0x1F801044L, "JOY_MCD_STAT", log);
		
		createNamedWord(fpa, program, 0x1F801048L, "JOY_MCD_MODE", log);
		createNamedWord(fpa, program, 0x1F80104AL, "JOY_MCD_CTRL", log);
		createNamedWord(fpa, program, 0x1F80104EL, "JOY_MCD_BAUD", log);
		
		createNamedDword(fpa, program, 0x1F801050L, "SIO_DATA", log);
		createNamedDword(fpa, program, 0x1F801054L, "SIO_STAT", log);
		
		createNamedWord(fpa, program, 0x1F801058L, "SIO_MODE", log);
		createNamedWord(fpa, program, 0x1F80105AL, "SIO_CTRL", log);
		createNamedWord(fpa, program, 0x1F80105CL, "SIO_MISC", log);
		createNamedWord(fpa, program, 0x1F80105EL, "SIO_BAUD", log);
	}
	
	private void addIntCtrl(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "INT_CTRL", 0x1F801070L, 6, true, false, log);
		
		createNamedWord(fpa, program, 0x1F801070L, "I_STAT", log);
		createNamedWord(fpa, program, 0x1F801074L, "I_MASK", log);
	}
	
	private void addDma(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "DMA_MDEC_IN", 0x1F801080L, 0x0C, true, false, log);
		createSegment(fpa, null, "DMA_MDEC_OUT", 0x1F801090L, 0x0C, true, false, log);
		createSegment(fpa, null, "DMA_GPU", 0x1F8010A0L, 0x0C, true, false, log);
		createSegment(fpa, null, "DMA_CDROM", 0x1F8010B0L, 0x0C, true, false, log);
		createSegment(fpa, null, "DMA_SPU", 0x1F8010C0L, 0x0C, true, false, log);
		createSegment(fpa, null, "DMA_PIO", 0x1F8010D0L, 0x0C, true, false, log);
		createSegment(fpa, null, "DMA_OTC", 0x1F8010E0L, 0x0C, true, false, log);
		createSegment(fpa, null, "DMA_CTRL_INT", 0x1F8010F0L, 0x08, true, false, log);
		
		createNamedDword(fpa, program, 0x1F801080L, "DMA_MDEC_IN_MADR", log);
		createNamedDword(fpa, program, 0x1F801084L, "DMA_MDEC_IN_BCR", log);
		createNamedDword(fpa, program, 0x1F801088L, "DMA_MDEC_IN_CHCR", log);
		
		createNamedDword(fpa, program, 0x1F801090L, "DMA_MDEC_OUT_MADR", log);
		createNamedDword(fpa, program, 0x1F801094L, "DMA_MDEC_OUT_BCR", log);
		createNamedDword(fpa, program, 0x1F801098L, "DMA_MDEC_OUT_CHCR", log);
		
		createNamedDword(fpa, program, 0x1F8010A0L, "DMA_GPU_MADR", log);
		createNamedDword(fpa, program, 0x1F8010A4L, "DMA_GPU_BCR", log);
		createNamedDword(fpa, program, 0x1F8010A8L, "DMA_GPU_CHCR", log);
		
		createNamedDword(fpa, program, 0x1F8010B0L, "DMA_CDROM_MADR", log);
		createNamedDword(fpa, program, 0x1F8010B4L, "DMA_CDROM_BCR", log);
		createNamedDword(fpa, program, 0x1F8010B8L, "DMA_CDROM_CHCR", log);
		
		createNamedDword(fpa, program, 0x1F8010C0L, "DMA_SPU_MADR", log);
		createNamedDword(fpa, program, 0x1F8010C4L, "DMA_SPU_BCR", log);
		createNamedDword(fpa, program, 0x1F8010C8L, "DMA_SPU_CHCR", log);
		
		createNamedDword(fpa, program, 0x1F8010D0L, "DMA_PIO_MADR", log);
		createNamedDword(fpa, program, 0x1F8010D4L, "DMA_PIO_BCR", log);
		createNamedDword(fpa, program, 0x1F8010D8L, "DMA_PIO_CHCR", log);
		
		createNamedDword(fpa, program, 0x1F8010E0L, "DMA_OTC_MADR", log);
		createNamedDword(fpa, program, 0x1F8010E4L, "DMA_OTC_BCR", log);
		createNamedDword(fpa, program, 0x1F8010E8L, "DMA_OTC_CHCR", log);
		
		createNamedDword(fpa, program, 0x1F8010F0L, "DMA_DPCR", log);
		createNamedDword(fpa, program, 0x1F8010F4L, "DMA_DICR", log);
	}
	
	private void addTimers(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "TMR_DOTCLOCK", 0x1F801100L, 0x10, true, false, log);
		createSegment(fpa, null, "TMR_HRETRACE", 0x1F801110L, 0x10, true, false, log);
		createSegment(fpa, null, "TMR_SYSCLOCK", 0x1F801120L, 0x10, true, false, log);
		
		createNamedDword(fpa, program, 0x1F801100L, "TMR_DOTCLOCK_VAL", log);
		createNamedDword(fpa, program, 0x1F801104L, "TMR_DOTCLOCK_MODE", log);
		createNamedDword(fpa, program, 0x1F801108L, "TMR_DOTCLOCK_MAX", log);
		
		createNamedDword(fpa, program, 0x1F801110L, "TMR_HRETRACE_VAL", log);
		createNamedDword(fpa, program, 0x1F801114L, "TMR_HRETRACE_MODE", log);
		createNamedDword(fpa, program, 0x1F801118L, "TMR_HRETRACE_MAX", log);
		
		createNamedDword(fpa, program, 0x1F801120L, "TMR_SYSCLOCK_VAL", log);
		createNamedDword(fpa, program, 0x1F801124L, "TMR_SYSCLOCK_MODE", log);
		createNamedDword(fpa, program, 0x1F801128L, "TMR_SYSCLOCK_MAX", log);
	}
	
	private void addCdromRegs(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "CDROM_REGS", 0x1F801800L, 4, true, false, log);
		
		createNamedByte(fpa, program, 0x1F801800L, "CDROM_REG0", log);
		createNamedByte(fpa, program, 0x1F801801L, "CDROM_REG1", log);
		createNamedByte(fpa, program, 0x1F801802L, "CDROM_REG2", log);
		createNamedByte(fpa, program, 0x1F801803L, "CDROM_REG3", log);
	}
	
	private void addGpuRegs(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "GPU_REGS", 0x1F801810L, 8, true, false, log);
		
		createNamedDword(fpa, program, 0x1F801810L, "GPU_REG0", log);
		createNamedDword(fpa, program, 0x1F801814L, "GPU_REG1", log);
	}
	
	private void addMdecRegs(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "MDEC_REGS", 0x1F801820L, 8, true, false, log);
		
		createNamedDword(fpa, program, 0x1F801820L, "MDEC_REG0", log);
		createNamedDword(fpa, program, 0x1F801824L, "MDEC_REG1", log);
	}
	
	private void addSpuVoices(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "SPU_VOICES", 0x1F801C00L, 0x10 * 24, true, false, log);
		
		for (int i = 0; i < 24; ++i) {
			createNamedDword(fpa, program, 0x1F801C00L + i * 0x10, String.format("VOICE_%02x_LEFT_RIGHT", i), log);
			createNamedWord(fpa, program, 0x1F801C00L + i * 0x10 + 0x04, String.format("VOICE_%02x_ADPCM_SAMPLE_RATE", i), log);
			createNamedWord(fpa, program, 0x1F801C00L + i * 0x10 + 0x06, String.format("VOICE_%02x_ADPCM_START_ADDR", i), log);
			createNamedWord(fpa, program, 0x1F801C00L + i * 0x10 + 0x08, String.format("VOICE_%02x_ADSR_ATT_DEC_SUS_REL", i), log);
			createNamedWord(fpa, program, 0x1F801C00L + i * 0x10 + 0x0C, String.format("VOICE_%02x_ADSR_CURR_VOLUME", i), log);
			createNamedWord(fpa, program, 0x1F801C00L + i * 0x10 + 0x0E, String.format("VOICE_%02x_ADPCM_REPEAT_ADDR", i), log);
		}
	}
	
	private void addSpuCtrlRegs(FlatProgramAPI fpa, Program program, MessageLog log) {
		createSegment(fpa, null, "SPU_CTRL_REGS", 0x1F801D80L, 0x40, true, false, log);
		
		createNamedWord(fpa, program, 0x1F801D80L, "SPU_MAIN_VOL_L", log);
		createNamedWord(fpa, program, 0x1F801D82L, "SPU_MAIN_VOL_R", log);
		createNamedWord(fpa, program, 0x1F801D84L, "SPU_REVERB_OUT_L", log);
		createNamedWord(fpa, program, 0x1F801D86L, "SPU_REVERB_OUT_R", log);
		createNamedDword(fpa, program, 0x1F801D88L, "SPU_VOICE_KEY_ON", log);
		createNamedDword(fpa, program, 0x1F801D8CL, "SPU_VOICE_KEY_OFF", log);
		createNamedDword(fpa, program, 0x1F801D90L, "SPU_VOICE_CHN_FM_MODE", log);
		createNamedDword(fpa, program, 0x1F801D94L, "SPU_VOICE_CHN_NOISE_MODE", log);
		createNamedDword(fpa, program, 0x1F801D98L, "SPU_VOICE_CHN_REVERB_MODE", log);
		createNamedDword(fpa, program, 0x1F801D9CL, "SPU_VOICE_CHN_ON_OFF_STATUS", log);
		createNamedWord(fpa, program, 0x1F801DA0L, "SPU_UNKN_1DA0", log);
		createNamedWord(fpa, program, 0x1F801DA2L, "SOUND_RAM_REVERB_WORK_ADDR", log);
		createNamedWord(fpa, program, 0x1F801DA4L, "SOUND_RAM_IRQ_ADDR", log);
		createNamedWord(fpa, program, 0x1F801DA6L, "SOUND_RAM_DATA_TRANSFER_ADDR", log);
		createNamedWord(fpa, program, 0x1F801DA8L, "SOUND_RAM_DATA_TRANSFER_FIFO", log);
		createNamedWord(fpa, program, 0x1F801DAAL, "SPU_CTRL_REG_CPUCNT", log);
		createNamedWord(fpa, program, 0x1F801DACL, "SOUND_RAM_DATA_TRANSTER_CTRL", log);
		createNamedWord(fpa, program, 0x1F801DAEL, "SPU_STATUS_REG_SPUSTAT", log);
		createNamedWord(fpa, program, 0x1F801DB0L, "CD_VOL_L", log);
		createNamedWord(fpa, program, 0x1F801DB2L, "CD_VOL_R", log);
		createNamedWord(fpa, program, 0x1F801DB4L, "EXT_VOL_L", log);
		createNamedWord(fpa, program, 0x1F801DB6L, "EXT_VOL_R", log);
		createNamedWord(fpa, program, 0x1F801DB8L, "CURR_MAIN_VOL_L", log);
		createNamedWord(fpa, program, 0x1F801DBAL, "CURR_MAIN_VOL_R", log);
		createNamedDword(fpa, program, 0x1F801DBCL, "SPU_UNKN_1DBC", log);
	}
	
	private void createNamedByte(FlatProgramAPI fpa, Program program, long address, String name, MessageLog log) {
		try {
			fpa.createByte(fpa.toAddr(address));
		} catch (Exception e) {
			log.appendException(e);
		}
		
		try {
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
}
	
	private void createNamedWord(FlatProgramAPI fpa, Program program, long address, String name, MessageLog log) {
		try {
			fpa.createWord(fpa.toAddr(address));
		} catch (Exception e) {
			log.appendException(e);
		}
		
		try {
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
}
	
	private void createNamedDword(FlatProgramAPI fpa, Program program, long address, String name, MessageLog log) {
		try {
			fpa.createDWord(fpa.toAddr(address));
		} catch (Exception e) {
			log.appendException(e);
		}
		
		try {
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	private void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
	
//	private void createMirrorSegment(Memory memory, FlatProgramAPI fpa, String name, long base, long new_addr, long size, MessageLog log) {
//		MemoryBlock block;
//		Address baseAddress = fpa.toAddr(base);
//		try {
//			block = memory.createByteMappedBlock(name, fpa.toAddr(new_addr), baseAddress, size);
//			MemoryBlock baseBlock = memory.getBlock(baseAddress);
//			block.setRead(baseBlock.isRead());
//			block.setWrite(baseBlock.isWrite());
//			block.setExecute(baseBlock.isExecute());
//		} catch (Exception e) {
//			log.appendException(e);
//		}
//	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {

		// TODO: If this loader has custom options, add them to 'list'
		//list.add(new Option("Option name goes here", "Default option value goes here"));

		return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}
}

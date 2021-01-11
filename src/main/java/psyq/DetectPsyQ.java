package psyq;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import psx.PsxAnalyzer;

public class DetectPsyQ {
	private final static byte[] VERSION_BYTES = new byte[] {      0x50,       0x73,       0x07, 0x00, 0x00, 0x00, 0x47,       0x00}; //, 0x07 - is a lib number, 0x47 - a version
	private final static byte[] VERSION_MASK = new byte[]  {(byte)0xFF, (byte)0xFF, (byte)0xE0, 0x00, 0x00, 0x00, 0x00, (byte)0xEE};
	private final static long VERSION_OFFSET = 0x06L;
	
	private static final List<String> OLD_VERSIONS = Arrays.asList("26", "30", "33", "34", "35");
	private static final String OLD_UNIQUE_LIB = "LIBGPU.LIB";
	private static final String OLD_UNIQUE_OBJ = "SYS.OBJ";
	
	public static String getPsyqVersion(Memory mem, final Address startAddress) throws MemoryAccessException, AddressOutOfBoundsException, FileNotFoundException, IOException {
		final Address result = mem.findBytes(startAddress, VERSION_BYTES, VERSION_MASK, true, TaskMonitor.DUMMY);
		
		if (result == null) {
			return getOldPsyqVersion(mem, startAddress);
		}
		
		short version = mem.getShort(result.add(VERSION_OFFSET), true);
		
		if ((version & 0xFF) == 0) {
			return String.format("%03X", version >> 4);
		}

		return String.format("%X", version);
	}
	
	private static String getOldPsyqVersion(Memory mem, final Address startAddress) throws FileNotFoundException, IOException {
		final File psyqDir = Application.getModuleDataSubDirectory("psyq").getFile(false);
		
		File [] dirs = psyqDir.listFiles(new FilenameFilter() {
		    @Override
		    public boolean accept(File dir, String name) {
		        return (new File(dir, name).isDirectory()) && OLD_VERSIONS.contains(name);
		    }
		});
		
		for (var verDir : dirs) {
			final String gameId = mem.getProgram().getName();
			final String libJsonFile = new File(verDir, String.format("%s.json", OLD_UNIQUE_LIB)).getAbsolutePath();
			final SigApplier sig = new SigApplier(gameId, libJsonFile, null, PsxAnalyzer.sequential, PsxAnalyzer.onlyFirst, PsxAnalyzer.minEntropy, TaskMonitor.DUMMY);
			
			final List<PsyqSig> signatures = sig.getSignatures();
			
			for (var item : signatures) {
				if (!item.getName().equals(OLD_UNIQUE_OBJ)) {
					continue;
				}
				
				final MaskedBytes bytes = item.getSig();
				
				final Address result = mem.findBytes(startAddress, bytes.getBytes(), bytes.getMasks(), true, TaskMonitor.DUMMY);
				
				if (result != null) {
					return verDir.getName() + '0';
				}
			}
		}
		
		return "";
	}
}

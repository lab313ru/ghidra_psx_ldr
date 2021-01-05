package psyq;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

public class DetectPsyQ {
	private final static byte[] VERSION_BYTES = new byte[] {      0x50,       0x73,       0x07, 0x00, 0x00, 0x00, 0x47,       0x00}; // 0x47 - a version
	private final static byte[] VERSION_MASK = new byte[]  {(byte)0xFF, (byte)0xFF, (byte)0xFF, 0x00, 0x00, 0x00, 0x00, (byte)0xF0};
	private final static long VERSION_OFFSET = 0x06L;
	private final static String[] PSYQ_SIG_VERSIONS = new String[] {
			"3.6", "4.0", "4.1",
			"4.2", "4.3", "4.4",
			"4.5", "4.6", "4.7"
	};
	
	public static String getPsyqVersion(Memory mem, Address startAddress) throws MemoryAccessException, AddressOutOfBoundsException {
		Address result = mem.findBytes(startAddress, VERSION_BYTES, VERSION_MASK, true, TaskMonitor.DUMMY);
		
		if (result == null) {
			return "";
		}

		short version = mem.getShort(result.add(VERSION_OFFSET), true);
		return String.format("%03X", version >> 4);
	}

	public static String[] getPsyqSigVersions() {
		return PSYQ_SIG_VERSIONS;
	}
}

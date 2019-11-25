package psyq;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

public class DetectPsyQ {
	private final static byte[] VERSION_BYTES = new byte[] {0x50, 0x73, 0x07, 0x00, 0x00, 0x00, 0x47, 0x00}; // 0x47 - a version
	private final static byte[] VERSION_MASK = new byte[] {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 0x00, (byte)0xFF};
	private final static long VERSION_OFFSET = 0x06L;
	
	public static String getPsyqVersion(Memory mem, Address startAddress) throws MemoryAccessException, AddressOutOfBoundsException {
		Address result = mem.findBytes(startAddress, VERSION_BYTES, VERSION_MASK, true, TaskMonitor.DUMMY);
		
		if (result == null) {
			return null;
		}
		
		byte version = mem.getByte(result.add(VERSION_OFFSET));
		return String.format("%02X", version);
	}
}

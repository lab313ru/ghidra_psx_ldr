package psx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class PsxExe implements StructConverter {
	
	public static final int HEADER_SIZE = 0x800;
	
	public static final String CODE_SEGM = "CODE";
	
	private static final String ASCII_ID = "PS-X EXE";
	private static final long ASCII_ID_OFF = 0;
	private static final int ASCII_ID_LEN = 8;
	
	private static final long INIT_PC_OFF = 0x10;
	private static final long INIT_GP_OFF = 0x14;
	private static final long ROM_ADDR_OFF = 0x18;
	private static final long ROM_SIZE_OFF = 0x1C;
	private static final long DATA_ADDR_OFF = 0x20;
	private static final long DATA_SIZE_OFF = 0x24;
	private static final long BSS_ADDR_OFF = 0x28;
	private static final long BSS_SIZE_OFF = 0x2C;
	private static final long SP_BASE_OFF = 0x30;
	private static final long SP_OFFSET_OFF = 0x34;
	
	private long initPc = 0, initGp = 0;
	private long romAddr = 0, romSize = 0;
	private long dataAddr = 0, dataSize = 0;
	private long bssAddr = 0, bssSize = 0;
	private long spBase = 0, spOff = 0;
	
	private boolean parsed = false;
	
	public PsxExe(BinaryReader reader) throws IOException {
		Parse(reader);
	}
	
	private void Parse(BinaryReader reader) throws IOException {
		if (reader.length() < HEADER_SIZE) {
			return;
		}
		
		String ascii_id = reader.readAsciiString(ASCII_ID_OFF, ASCII_ID_LEN);
		
		if (!ascii_id.equals(ASCII_ID)) {
			return;
		}
		
		initPc = reader.readUnsignedInt(INIT_PC_OFF);
		initGp = reader.readUnsignedInt(INIT_GP_OFF);
		
		romAddr = reader.readUnsignedInt(ROM_ADDR_OFF);
		romSize = reader.readUnsignedInt(ROM_SIZE_OFF);
		
		dataAddr = reader.readUnsignedInt(DATA_ADDR_OFF);
		dataSize = reader.readUnsignedInt(DATA_SIZE_OFF);
		
		bssAddr = reader.readUnsignedInt(BSS_ADDR_OFF);
		bssSize = reader.readUnsignedInt(BSS_SIZE_OFF);
		
		spBase = reader.readUnsignedInt(SP_BASE_OFF);
		spOff = reader.readUnsignedInt(SP_OFFSET_OFF);
		
		parsed = true;
	}
	
	public long getRomStart() {
		return romAddr;
	}

	public long getRomSize() {
		return romSize;
	}
	
	public long getRomEnd() {
		return romAddr + romSize;
	}

	public long getDataAddr() {
		return dataAddr;
	}

	public long getDataSize() {
		return dataSize;
	}

	public long getBssAddr() {
		return bssAddr;
	}

	public long getBssSize() {
		return bssSize;
	}

	public long getSpBase() {
		return spBase;
	}

	public long getSpOff() {
		return spOff;
	}

	public boolean isParsed() {
		return parsed;
	}

	public long getInitPc() {
		return initPc;
	}
	
	public long getInitGp() {
		return initGp;
	}
	
	public void setInitGp(long value) {
		initGp = value & 0xFFFFFFFFL;
	}

	@Override
	public DataType toDataType() {
		Structure s = new StructureDataType("PsxHeader", 0);
		
		s.add(ASCII, 16, "ascii_id", null);
		
		s.add(POINTER, 4, "init_pc", null);
		s.add(POINTER, 4, "init_gp", null);
		
		s.add(POINTER, 4, "ram_addr", null);
		s.add(DWORD, 4, "ram_size", null);
		
		s.add(POINTER, 4, "data_addr", null);
		s.add(DWORD, 4, "data_size", null);
		
		s.add(POINTER, 4, "bss_addr", null);
		s.add(DWORD, 4, "bss_size", null);
		
		s.add(POINTER, 4, "sp_base", null);
		s.add(DWORD, 4, "sp_offs", null);
		
		s.add(ASCII, 0x14, "reserved_a", null);
		s.add(ASCII, HEADER_SIZE - 0x4C, "marker", null);
		
		return s;
	}

}

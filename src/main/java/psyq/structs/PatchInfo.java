package psyq.structs;

import java.io.IOException;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.udojava.evalex.Expression;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;

public final class PatchInfo {
	private final int type;
	private final int offset;
	private final int patchOffset;
	private final int sectionIndex;
	private String reference;
	private boolean toExternal = false;
	private int externalIndex = 0;

	public final int getType() {
		return type;
	}

	public final int getOffset() {
		return patchOffset + offset;
	}
	
	public final int getSectionIndex() {
		return sectionIndex;
	}
	
	public String getReference() {
		return reference;
	}
	
	public boolean isExternal() {
		return toExternal;
	}
	
	public int getExternalIndex() {
		return externalIndex;
	}

	public PatchInfo(int patchOffset, int sectionIndex, BinaryReader reader, MessageLog log) throws IOException {
		this.type = reader.readNextByte();
		this.patchOffset = patchOffset;
		this.offset = reader.readNextUnsignedShort();
		this.sectionIndex = sectionIndex;
		
		reference = "";
		
		readPatchInfo(reader, log);
	}
	
	public long calcReference(HashMap<Integer, Symbol> symbols) throws NumberFormatException {
		toExternal = false;
		externalIndex = 0;
		
		String ref = reference;
		ref = ref.replaceAll("\\$([0-9A-Fa-f]+)", "0x$1");
		
		Matcher m = Pattern.compile("\\[([0-9A-Fa-f]+)\\]").matcher(ref);
		while (m.find()) {
			externalIndex = Integer.parseInt(m.group(1), 16);
			long address = symbols.get(externalIndex).getAddress();
			ref = ref.substring(0, m.start()) + String.format("0x%X", address) + ref.substring(m.end());
			toExternal = true;
		}
		
		m = Pattern.compile("sectbase\\(([0-9A-Fa-f]+)\\)").matcher(ref);
		while (m.find()) {
			int sectIndex = Integer.parseInt(m.group(1), 16);
			long address = symbols.get(sectIndex).getAddress();
			ref = ref.substring(0, m.start()) + String.format("0x%X", address) + ref.substring(m.end());
		}
		
		m = Pattern.compile("sectstart\\(([0-9A-Fa-f]+)\\)").matcher(ref);
		while (m.find()) {
			int sectIndex = Integer.parseInt(m.group(1), 16);
			long address = symbols.get(sectIndex).getAddress();
			ref = ref.substring(0, m.start()) + String.format("0x%X", address) + ref.substring(m.end());
		}
		
		m = Pattern.compile("sectend\\(([0-9A-Fa-f]+)\\)").matcher(ref);
		while (m.find()) {
			int sectIndex = Integer.parseInt(m.group(1), 16);
			Symbol sect = symbols.get(sectIndex);
			long address = sect.getAddress() + sect.getLength();
			ref = ref.substring(0, m.start()) + String.format("0x%X", address) + ref.substring(m.end());
		}
		
		ref = ref.replaceAll("\\!", "\\+");
		
		m = Pattern.compile("0x([0-9A-Fa-f]+) \\- 0x([0-9A-Fa-f]+)").matcher(ref);
		
		if (m.find()) {
			int val1 = Integer.parseInt(m.group(1), 16);
			int val2 = Integer.parseInt(m.group(2), 16);
			
			if (val1 < val2) {
				ref = String.format("0x%X - 0x%X", val2, val1);
			}
		}

		m = Pattern.compile("0x([0-9A-Fa-f]+) \\- \\(0x([0-9A-Fa-f]+) \\+ 0x([0-9A-Fa-f]+)\\)").matcher(ref);
		
		if (m.find()) {
			int val1 = Integer.parseInt(m.group(1), 16);
			int val2 = Integer.parseInt(m.group(2), 16);
			int val3 = Integer.parseInt(m.group(3), 16);
			
			if (val1 < (val2 + val3)) {
				ref = String.format("(0x%X + 0x%X) - 0x%X", val2, val3, val1);
			}
		}
		
		m = Pattern.compile("0x([0-9A-Fa-f]+) / \\(0x([0-9A-Fa-f]+) \\- 0x([0-9A-Fa-f]+)\\)").matcher(ref);
		
		if (m.find()) {
			int val1 = Integer.parseInt(m.group(1), 16);
			int val2 = Integer.parseInt(m.group(2), 16);
			int val3 = Integer.parseInt(m.group(3), 16);
			
			ref = String.format("(0x%X - 0x%X) / 0x%X", val2, val3, val1);
		}
		
		return new Expression(ref).eval().longValue() & 0xFFFFFFFF;
	}
	
	private void readPatchInfo(BinaryReader reader, MessageLog log) throws IOException {
		byte tagType = reader.readNextByte();
		
		switch (tagType) {
		case 0: {
			reference += String.format("$%X", reader.readNextUnsignedInt());
		} break;
		case 2: {
			int refIndex = reader.readNextUnsignedShort();
			reference += String.format("[%X]", refIndex);
		} break;
		case 4: {
			reference += String.format("sectbase(%X)", reader.readNextUnsignedShort());
		} break;
//		case 6: {
//			reference += String.format("bank(%X)", reader.readNextUnsignedShort());
//		} break;
//		case 8: {
//			reference += String.format("sectof(%X)", reader.readNextUnsignedShort());
//		} break;
//		case 10: {
//			reference += String.format("offs(%X)", reader.readNextUnsignedShort());
//		} break;
		case 12: {
			reference += String.format("sectstart(%X)", reader.readNextUnsignedShort());
		} break;
//		case 14: {
//			reference += String.format("groupstart(%X)", reader.readNextUnsignedShort());
//		} break;
//		case 16: {
//			reference += String.format("groupof(%X)", reader.readNextUnsignedShort());
//		} break;
//		case 18: {
//			reference += String.format("seg(%X)", reader.readNextUnsignedShort());
//		} break;
//		case 20: {
//			reference += String.format("grouporg(%X)", reader.readNextUnsignedShort());
//		} break;
		case 22: {
			reference += String.format("sectend(%X)", reader.readNextUnsignedShort());
		} break;
//		case 24: {
//			reference += String.format("groupend(%X)", reader.readNextUnsignedShort());
//		} break;
		default: {
			reference += "(";
			readPatchInfo(reader, log);
			
			switch (tagType) {
//			case 0x20: {
//				reference += "=";
//			} break;
//			case 0x22: {
//				reference += "<>";
//			} break;
//			case 0x24: {
//				reference += "<=";
//			} break;
//			case 0x26: {
//				reference += "<";
//			} break;
//			case 0x28: {
//				reference += ">=";
//			} break;
//			case 0x2A: {
//				reference += ">";
//			} break;
			case 0x2C: {
				reference += " + ";
			} break;
			case 0x2E: {
				reference += " - ";
			} break;
//			case 0x30: {
//				reference += "*";
//			} break;
			case 0x32: {
				reference += " / ";
			} break;
//			case 0x34: {
//				reference += "&";
//			} break;
			case 0x36: {
				reference += " ! ";
			} break;
//			case 0x38: {
//				reference += "^";
//			} break;
//			case 0x3A: {
//				reference += "<<";
//			} break;
//			case 0x3C: {
//				reference += ">>";
//			} break;
//			case 0x3E: {
//				reference += "%";
//			} break;
//			case 0x40: {
//				reference += "---";
//			} break;
//			case 0x42: {
//				reference += "-revword-";
//			} break;
//			case 0x44: {
//				reference += "-check0-";
//			} break;
//			case 0x46: {
//				reference += "-check1-";
//			} break;
//			case 0x48: {
//				reference += "-bitrange-";
//			} break;
//			case 0x4A: {
//				reference += "-arshift_chk-";
//			} break;
			default: {
				log.appendException(new Exception(String.format("Unknown patch type: %02X", type)));
			} break;
			}
			
			readPatchInfo(reader, log);
			
			reference += ")";
		} break;
		}
	}
}

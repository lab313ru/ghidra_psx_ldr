package psyq.sym;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;

public class SymFile {
	private List<SymObject> objects = new ArrayList<>();
	
	public static SymFile fromBinary(String path) {
		try {
			ByteProvider provider = new RandomAccessByteProvider(new File(path));
			BinaryReader reader = new BinaryReader(provider, true);
			return new SymFile(reader);
		} catch (IOException e) {
			return null;
		}
	}

	private SymFile(BinaryReader reader) throws IOException {
		String sig = reader.readNextNullTerminatedAsciiString();
		
		if (!sig.equals("MND")) {
			throw new IOException("Wrong MND signature");
		}
		
		reader.readNextByte(); // version
		reader.readNextByte(); // unit
		reader.readNextByteArray(3); // skip
		
		SymFunc symFunc = null;
		
		while (true) {
			long offset = 0;
			byte tag = 0;

			while (true) {
				offset = reader.readNextUnsignedInt();
				tag = reader.readNextByte();
				
				if (tag != 8) {
					break;
				}
				
				reader.readNextByte(); // MX-info
			}
			
			if (tag <= 0x7F) {
				String name = reader.readNextAsciiString();
				SymObject obj = new SymObjectName(offset, tag, name);
				objects.add(obj);
				continue;
			}
			
			switch (tag) {
			case (byte)0x80: {
			} break;
			case (byte)0x82: {
				reader.readNextByte(); // line byte_add
			} break;
			case (byte)0x84: {
				reader.readNextUnsignedShort(); // line word_add
			} break;
			case (byte)0x86: {
				reader.readNextUnsignedInt(); // new line_num
			} break;
			case (byte)0x88: {
				reader.readNextUnsignedInt(); // new line_num
				reader.readNextAsciiString(); // new line_num to file_name
			} break;
			case (byte)0x8A: {
			} break;
			case (byte)0x8C: {
				reader.readNextUnsignedShort(); // fp
				reader.readNextUnsignedInt(); // fsize
				reader.readNextUnsignedShort(); // retreg
				reader.readNextUnsignedInt(); // mask
				reader.readNextUnsignedInt(); // maskoffs
				reader.readNextUnsignedInt(); // line
				String fileName = reader.readNextAsciiString();
				String funcName = reader.readNextAsciiString();
				
				symFunc = new SymFunc(fileName, funcName, offset);
			} break;
			case (byte)0x8E: {
				reader.readNextUnsignedInt(); // func end line
				if (symFunc == null) {
					throw new IOException("End of non-started function");
				}
				
				symFunc.setEndOffset(offset);
				objects.add(symFunc);
				symFunc = null;
			} break;
			case (byte)0x90: {
				reader.readNextUnsignedInt(); // block start line
			} break;
			case (byte)0x92: {
				reader.readNextUnsignedInt(); // block end line
			} break;
			case (byte)0x94:
			case (byte)0x96: {
				SymDefClass classDef = SymDefClass.fromInt(reader.readNextUnsignedShort());
				SymDefType classType = new SymDefType(reader.readNextUnsignedShort());
				long size = reader.readNextUnsignedInt();
				
				List<Long> dims = null;
				String defTag = null;
				
				if (tag == (byte)0x96) {
					long dimsCount = reader.readNextUnsignedInt();
					dims = new ArrayList<>();
					
					for (long i = 0; i < dimsCount; ++i) {
						dims.add(reader.readNextUnsignedInt());
					}
					
					defTag = reader.readNextAsciiString();
				}
				
				String defName = reader.readNextAsciiString();
				
				SymDef def2 = new SymDef(classDef, classType, size, defName, offset);
				
				if (tag == (byte)0x96) {
					def2.setDims(dims.toArray(Long[]::new));
					def2.setDefTag(defTag);
				}
				objects.add(def2);
				
				switch (classDef) {
				case ARG:
				case REGPARM: {
					if (symFunc == null) {
						throw new IOException("Parameter for non-started function");
					}
					
					symFunc.addArgument(def2);
				} break;
				default: break;
				}
			} break;
			case (byte)0x98: {
				reader.readNextUnsignedInt(); // ovr_length
				reader.readNextUnsignedInt(); // ovr_id
			} break;
			case (byte)0x9A: {
			} break;
			case (byte)0x9C: {
				reader.readNextUnsignedShort(); // fp
				reader.readNextUnsignedInt(); // fsize
				reader.readNextUnsignedShort(); // retreg
				reader.readNextUnsignedInt(); // mask
				reader.readNextUnsignedInt(); // maskoffs
				reader.readNextUnsignedInt(); // fmask
				reader.readNextUnsignedInt(); // fmaskoffs
				reader.readNextUnsignedInt(); // line
				String fileName = reader.readNextAsciiString();
				String funcName = reader.readNextAsciiString();
				
				symFunc = new SymFunc(fileName, funcName, offset);
			} break;
			case (byte)0x9E: {
				reader.readNextAsciiString(); // mangled name1
				reader.readNextAsciiString(); // mangled name2
			} break;
			}
		}
	}
	
	public SymObject[] getObjects() {
		return objects.toArray(SymObject[]::new);
	}
}

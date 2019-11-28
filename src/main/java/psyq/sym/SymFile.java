package psyq.sym;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
		String sig = reader.readNextAsciiString(3);
		
		if (!sig.equals("MND")) {
			throw new IOException("Wrong MND signature");
		}
		
		reader.readNextUnsignedByte(); // version
		reader.readNextUnsignedByte(); // unit
		reader.readNextByteArray(3); // skip
		
		SymStructUnionEnum currStructUnion = null;
		SymFunc currFunc = null;
		Map<String, SymFunc> defFuncs = new HashMap<>();
		
		while (reader.getPointerIndex() < reader.length()) {
			long offset = 0;
			int tag = 0;

			while (true) {
				offset = reader.readNextUnsignedInt();
				tag = reader.readNextUnsignedByte();
				
				if (tag != 8) {
					break;
				}
				
				reader.readNextUnsignedByte(); // MX-info
			}
			
			if (tag <= 0x7F) {
				String name = readString(reader);
				SymName obj = new SymName(offset, name);
				objects.add(obj);
				continue;
			}
			
			switch (tag) {
			case 0x80: {
			} break;
			case 0x82: {
				reader.readNextUnsignedByte(); // line byte_add
			} break;
			case 0x84: {
				reader.readNextUnsignedShort(); // line word_add
			} break;
			case 0x86: {
				reader.readNextUnsignedInt(); // new line_num
			} break;
			case 0x88: {
				reader.readNextUnsignedInt(); // new line_num
				readString(reader); // new line_num to file_name
			} break;
			case 0x8A: {
			} break;
			case 0x8C: 
			case 0x9C: {
				reader.readNextUnsignedShort(); // fp
				reader.readNextUnsignedInt(); // fsize
				reader.readNextUnsignedShort(); // retreg
				reader.readNextUnsignedInt(); // mask
				reader.readNextUnsignedInt(); // maskoffs
				
				if (tag == 0x9C) {
					reader.readNextUnsignedInt(); // fmask
					reader.readNextUnsignedInt(); // fmaskoffs
				}
				
				reader.readNextUnsignedInt(); // line
				String fileName = readString(reader);
				String funcName = readString(reader); // funcName
				
				SymFunc func = currFunc = defFuncs.get(funcName);
				
				if (func == null) {
					func = currFunc = new SymFunc(
							offset,
							new SymDefType(new SymDefTypePrimitive[] {SymDefTypePrimitive.FCN, SymDefTypePrimitive.VOID}),
							funcName);
				}
				
				func.setFileName(fileName);

				defFuncs.put(funcName, func);
			} break;
			case 0x8E: {
				reader.readNextUnsignedInt(); // func end line
				if (currFunc == null) {
					throw new IOException("End of non-started function");
				}
				
				currFunc.setEndOffset(offset);
				currFunc = null;
			} break;
			case 0x90: {
				reader.readNextUnsignedInt(); // block start line
			} break;
			case 0x92: {
				reader.readNextUnsignedInt(); // block end line
			} break;
			case 0x94:
			case 0x96: {
				SymDefClass defClass = SymDefClass.fromInt(reader.readNextUnsignedShort());
				SymDefType defType = new SymDefType(reader.readNextUnsignedShort());
				long size = reader.readNextUnsignedInt();
				
				List<Long> dims = null;
				String defTag = null;
				
				if (tag == 0x96) {
					int dimsCount = reader.readNextUnsignedShort();
					dims = new ArrayList<>();
					
					for (int i = 0; i < dimsCount; ++i) {
						dims.add(reader.readNextUnsignedInt());
					}
					
					defTag = readString(reader);
				}
				
				String defName = readString(reader);
				
				SymDef def2 = new SymDef(defClass, defType, size, defName, offset);
				
				if (tag == 0x96) {
					def2.setDims(dims.toArray(Long[]::new));
					def2.setDefTag(defTag);
				}
				objects.add(def2);
				
				switch (defClass) {
				case ARG:
				case REGPARM: {
					if (currFunc == null) {
						throw new IOException("Parameter for non-started function");
					}

					currFunc.addArgument(def2);
				} break;
				case EXT: {
					SymDefTypePrimitive[] typesList = defType.getTypesList();
					
					if (typesList.length >= 1 && typesList[0] == SymDefTypePrimitive.FCN) {
						SymFunc func = new SymFunc(offset, defType, defName);
						defFuncs.put(defName, func);
					}
				} break;
				// STRUCT or UNION begin
				case STRTAG:
				case UNTAG: {
					SymDefTypePrimitive[] typesList = defType.getTypesList();
					
					if (typesList.length != 1 ||
							typesList[0] != SymDefTypePrimitive.STRUCT ||
							typesList[0] != SymDefTypePrimitive.UNION) {
						throw new IOException("Wrong STRTAG (or UNTAG) type");
					}
					
					currStructUnion = new SymStructUnionEnum(defName, size, typesList[0]);
				} break;
				// STRUCT or UNION fields
				case MOS:
				case MOU: {
					if (currStructUnion == null) {
						throw new IOException("Non-defined struct (or union) field definition");
					}
					
					currStructUnion.addField(def2);
				} break;
				// STRUCT or UNION end
				case EOS: {
					if (currStructUnion == null) {
						throw new IOException("End of non-defined struct (or union)");
					}
					
					SymDefTypePrimitive[] typesList = defType.getTypesList();
					
					if (typesList.length != 1 || typesList[0] != SymDefTypePrimitive.NULL || dims.get(0) != 0) {
						throw new IOException("Wrong EOS type");
					}
					
					objects.add(currStructUnion);
				} break;
				// ENUM begin
				case ENTAG: {
					
				} break;
				default: break;
				}
			} break;
			case 0x98: {
				reader.readNextUnsignedInt(); // ovr_length
				reader.readNextUnsignedInt(); // ovr_id
			} break;
			case 0x9A: {
			} break;
			case 0x9E: {
				readString(reader); // mangled name1
				readString(reader); // mangled name2
			} break;
			}
		}
		
		objects.addAll(defFuncs.values());
	}
	
	private static String readString(BinaryReader reader) throws IOException {
		return reader.readNextAsciiString(reader.readNextUnsignedByte());
	}
	
	public SymObject[] getObjects() {
		return objects.toArray(SymObject[]::new);
	}
}

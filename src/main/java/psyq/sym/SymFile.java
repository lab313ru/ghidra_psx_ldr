package psyq.sym;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import psx.PsxLoader;

public class SymFile {
	private List<SymObject> objects = new ArrayList<>();
	
	public static SymFile fromBinary(String path) {
		try {
			FileInputStream fis = new FileInputStream(path);
			byte[] fileData = fis.readAllBytes();
			fis.close();
			
			ByteArrayProvider provider = new ByteArrayProvider(fileData);
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
							new SymDef(SymDefClass.EXT,
									new SymDefType(new SymDefTypePrim[] {SymDefTypePrim.FCN, SymDefTypePrim.VOID}), false, 0L, funcName, offset),
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
				
				List<Integer> dims = null;
				String defTag = null;
				
				if (tag == 0x96) {
					int dimsCount = reader.readNextUnsignedShort();
					dims = new ArrayList<>();
					
					for (int i = 0; i < dimsCount; ++i) {
						dims.add((int)reader.readNextUnsignedInt());
					}
					
					defTag = readString(reader);
				}
				
				String defName = readString(reader);
				
				SymDef def2 = new SymDef(defClass, defType, tag == 0x96, size, defName, offset);
				
				if (tag == 0x96) {
					def2.setDims(dims.toArray(Integer[]::new));
					def2.setTag(defTag);
				}
				
				switch (defClass) {
				case ARG:
				case REGPARM: {
					if (currFunc == null) {
						throw new IOException("Parameter for non-started function");
					}

					currFunc.addArgument(def2);
				} break;
				case EXT:
				case STAT: {
					SymDefTypePrim[] typesList = defType.getTypesList();
					
					if (typesList.length >= 1 && typesList[0] == SymDefTypePrim.FCN) {
						SymFunc func = new SymFunc(offset, def2, defName);
						defFuncs.put(defName, func);
					}
				} break;
				case TPDEF: {
					objects.add(new SymTypedef(def2));
				} break;
				// STRUCT, UNION, ENUM begin
				case STRTAG:
				case UNTAG:
				case ENTAG: {
					SymDefTypePrim[] typesList = defType.getTypesList();
					
					if (typesList.length != 1 ||
							(typesList[0] != SymDefTypePrim.STRUCT &&
							typesList[0] != SymDefTypePrim.UNION &&
							typesList[0] != SymDefTypePrim.ENUM)) {
						throw new IOException("Wrong struct|union|enum type");
					}
					
					currStructUnion = new SymStructUnionEnum(defName, size, typesList[0]);
				} break;
				// STRUCT, UNION, ENUM fields
				case MOS:
				case MOU:
				case MOE: {
					if (currStructUnion == null) {
						throw new IOException("Non-defined struct|union|enum field definition");
					}
					
					currStructUnion.addField(def2);
				} break;
				// STRUCT, UNION, ENUM end
				case EOS: {
					if (currStructUnion == null) {
						throw new IOException("End of non-defined struct|union|enum");
					}
					
					SymDefTypePrim[] typesList = defType.getTypesList();
					
					if (typesList.length != 1 || typesList[0] != SymDefTypePrim.NULL || dims.size() != 0) {
						throw new IOException("Wrong EOS type");
					}
					
					objects.add(currStructUnion);
					currStructUnion = null;
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
	
	public void applySymbols(SymbolTable st, FlatProgramAPI fpa, MessageLog log, TaskMonitor monitor) {
		DataTypeManager mgr = fpa.getCurrentProgram().getDataTypeManager();
		
		List<SymObject> tryAgain = new ArrayList<>();
		
		monitor.setMessage("Applying SYM objects...");
		monitor.setMaximum(objects.size());
		
		for (int i = 0; i < objects.size(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			
			SymObject obj = objects.get(i);
			
			Address addr = fpa.toAddr(obj.getOffset());
			
			if (!applySymbol(obj, addr, st, fpa, mgr, log)) {
				tryAgain.add(obj);
			}
			
			monitor.setProgress(i + 1);
		}
		
		monitor.setMessage("Applying SYM objects: done");
		monitor.setMessage("Applying SYM forward usage objects...");
		monitor.setMaximum(tryAgain.size());
		
		int c = 0;
		Iterator<SymObject> i = tryAgain.iterator();
		
		while (i.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			
			SymObject obj = i.next();
			Address addr = fpa.toAddr(obj.getOffset());
			
			if (applySymbol(obj, addr, st, fpa, mgr, log)) {
				i.remove();
				c++;
				
				monitor.setProgress(c);
			}
		}
	}
	
	@SuppressWarnings("incomplete-switch")
	private static boolean applySymbol(SymObject obj, Address addr, SymbolTable st, FlatProgramAPI fpa,
			DataTypeManager mgr, MessageLog log) {
		if (obj instanceof SymFunc) {
			SymFunc sf = (SymFunc)obj;
			PsxLoader.setFunction(st, fpa, addr, sf.getFuncName(), true, false, log);
			setFunctionArguments(fpa, sf, log);
			fpa.setPlateComment(addr, String.format("File: %s", sf.getFileName()));
		} else if (obj instanceof SymName) {
			SymName sn = (SymName)obj;
			try {
				st.createLabel(addr, sn.getObjectName(), SourceType.ANALYSIS);
			} catch (InvalidInputException e) {
				log.appendException(e);
			}
		} else if (obj instanceof SymTypedef) {
			SymTypedef tpdef = (SymTypedef)obj;
			SymDef def = tpdef.getDefinition();
			
			DataType dt = def.getDataType(mgr);
			
			if (dt == null) {
				return false;
			}
			
			DataType baseType = new TypedefDataType(tpdef.getName(), dt);
			
			if (mgr.getDataType(baseType.getDataTypePath()) == null) {
				mgr.addDataType(baseType, DataTypeConflictHandler.REPLACE_HANDLER);
			}
		} else if (obj instanceof SymStructUnionEnum) {
			SymStructUnionEnum ssu = (SymStructUnionEnum)obj;
			SymDefTypePrim type = ssu.getType();
			SymDef[] fields = ssu.getFields();
			
			switch (type) {
			case UNION: {
				UnionDataType udt = new UnionDataType(ssu.getName());
				udt.setMinimumAlignment(4);
				
				Union uut = (Union)mgr.addDataType(udt, DataTypeConflictHandler.REPLACE_HANDLER);
				
				for (SymDef field : fields) {
					DataType dt = field.getDataType(mgr);
					
					if (dt == null) {
						mgr.remove(uut, TaskMonitor.DUMMY);
						return false;
					}
					
					uut.add(dt, field.getName(), null);
				}
			} break;
			case STRUCT: {
				StructureDataType sdt = new StructureDataType(ssu.getName(), 0);
				sdt.setMinimumAlignment(4);
				
				Structure ddt = (Structure)mgr.addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER);
				
				for (SymDef field : fields) {
					DataType dt = field.getDataType(mgr);
					
					if (dt == null) {
						mgr.remove(ddt, TaskMonitor.DUMMY);
						return false;
					}
					
					ddt.add(dt, field.getName(), null);
				}
			} break;
			case ENUM: {
				EnumDataType edt = new EnumDataType(ssu.getName(), (int)ssu.getSize());
				
				for (SymDef field : fields) {
					edt.add(field.getName(), field.getOffset());
				}
				
				mgr.addDataType(edt, DataTypeConflictHandler.REPLACE_HANDLER);
			} break;
			}
		}
		
		return true;
	}
	
	private static void setFunctionArguments(FlatProgramAPI fpa, SymFunc funcDef, MessageLog log) {
		try {
			Program program = fpa.getCurrentProgram();
			DataTypeManager mgr = program.getDataTypeManager();
			Function func = fpa.getFunctionAt(fpa.toAddr(funcDef.getOffset()));
			
			DataType dt = funcDef.getReturnType().getDataType(mgr);
			
			if (dt != null) {
				func.setReturnType(dt, SourceType.ANALYSIS);
			}
			
			List<ParameterImpl> params = new ArrayList<>();
			SymDef[] args = funcDef.getArguments();
			for (int i = 0; i < args.length; ++i) {
				params.add(new ParameterImpl(args[i].getName(), args[i].getDataType(mgr), program));
			}
			
			func.updateFunction("__stdcall", null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
					SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
		} catch (Exception e) {
			log.appendException(e);
		}
	}
	
	private static String readString(BinaryReader reader) throws IOException {
		return reader.readNextAsciiString(reader.readNextUnsignedByte());
	}
	
	public SymObject[] getObjects() {
		return objects.toArray(SymObject[]::new);
	}
}

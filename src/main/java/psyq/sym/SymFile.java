package psyq.sym;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import psx.PsxLoader;

public class SymFile {
	private Set<SymObject> types = new HashSet<>();
	private List<SymName> names = new ArrayList<>();
	private List<SymDefinition> namesWithTypes = new ArrayList<>();
	private Map<String, SymStructUnionEnum> fakeObjs = new HashMap<>();
	private Map<String, SymFunc> funcs = new HashMap<>();
	private List<SymOverlay> overlays = new ArrayList<>();
	
	public static SymFile fromBinary(String path, Program program, MessageLog log, TaskMonitor monitor) {
		try {
			FileInputStream fis = new FileInputStream(path);
			byte[] fileData = fis.readAllBytes();
			fis.close();
			
			ByteArrayProvider provider = new ByteArrayProvider(fileData);
			BinaryReader reader = new BinaryReader(provider, true);
			return new SymFile(reader, program, log, monitor);
		} catch (IOException e) {
			log.appendException(e);
			return null;
		}
	}

	private SymFile(BinaryReader reader, Program program, MessageLog log, TaskMonitor monitor) throws IOException {
		String sig = reader.readNextAsciiString(3);
		
		if (!sig.equals("MND")) {
			throw new IOException("Wrong MND signature");
		}
		
		reader.readNextUnsignedByte(); // version
		reader.readNextUnsignedByte(); // unit
		reader.readNextByteArray(3); // skip
		
		SymStructUnionEnum currStructUnion = null;
		String currFuncName = null;
		long currOverlay = 0L;
		
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
				SymName obj = new SymName(name, offset, currOverlay);
				names.add(obj);
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
				String funcName = currFuncName = readString(reader); // funcName
				
				SymFunc func = funcs.get(funcName);
				
				if (func == null) {
					func = new SymFunc(new SymDefinition(SymClass.EXT,
									   new SymType(new SymTypePrimitive[] {SymTypePrimitive.FCN, SymTypePrimitive.VOID}),
									               null, null, 0L, funcName, offset, currOverlay));
				}
				
				func.setFileName(fileName);

				funcs.put(funcName, func);
			} break;
			case 0x8E: {
				reader.readNextUnsignedInt(); // func end line
				
				SymFunc func = funcs.get(currFuncName);
				
				if (func == null) {
					throw new IOException("End of non-started function");
				}
				
				func.setEndOffset(offset);
				funcs.put(currFuncName, func);
				currFuncName = null;
			} break;
			case 0x90: {
				reader.readNextUnsignedInt(); // block start line
			} break;
			case 0x92: {
				reader.readNextUnsignedInt(); // block end line
			} break;
			case 0x94:
			case 0x96: {
				SymClass defClass = SymClass.fromInt(reader.readNextUnsignedShort());
				SymType defType = new SymType(reader.readNextUnsignedShort());
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
				
				SymDefinition def2 = new SymDefinition(defClass, defType, defTag, (dims != null) ? dims.toArray(Integer[]::new) : null, size, defName, offset, currOverlay);
				
				switch (defClass) {
				case ARG:
				case REGPARM: {
					if (currFuncName == null) {
						throw new IOException("Parameter for non-started function");
					}
					
					if (fakeObjs.containsKey(defTag)) {
						SymStructUnionEnum obj = fakeObjs.get(defTag);
						def2.setTag(obj.getName());
					}
					
					SymFunc func = funcs.get(currFuncName);
					func.addArgument(def2);
					funcs.put(currFuncName, func);
				} break;
				case EXT:
				case STAT: {
					SymTypePrimitive[] typesList = defType.getTypesList();
					
					if (typesList.length >= 1 && typesList[0] == SymTypePrimitive.FCN) {
						SymFunc func = new SymFunc(def2);
						funcs.put(defName, func);
					} else if (currFuncName == null) { // exclude function blocks
						if (fakeObjs.containsKey(defTag)) {
							SymStructUnionEnum obj = fakeObjs.get(defTag);
							def2.setTag(obj.getName());
						}
						
						namesWithTypes.add(def2);
					}
				} break;
				case TPDEF: {
					if (fakeObjs.containsKey(defTag)) {
						SymStructUnionEnum obj = fakeObjs.get(defTag);
						obj.setName(defName);
						fakeObjs.replace(defTag, obj);
						types.add(obj);
					} else {
						types.add(new SymTypedef(def2));
					}
				} break;
				// STRUCT, UNION, ENUM begin
				case STRTAG:
				case UNTAG:
				case ENTAG: {
					currStructUnion = new SymStructUnionEnum(defName, size, defType.getPrimaryType());
				} break;
				// STRUCT, UNION, ENUM fields
				case MOS:
				case MOU:
				case MOE: {
					if (currStructUnion == null) {
						throw new IOException("Non-defined struct|union|enum field definition");
					}
					
					if (fakeObjs.containsKey(defTag)) {
						SymStructUnionEnum obj = fakeObjs.get(defTag);
						def2.setTag(obj.getName());
					}
					
					currStructUnion.addField(def2);
				} break;
				// STRUCT, UNION, ENUM end
				case EOS: {
					if (currStructUnion == null) {
						throw new IOException("End of non-defined struct|union|enum");
					}

					if (defType.getPrimaryType() != SymTypePrimitive.NULL || dims.size() != 0) {
						throw new IOException("Wrong EOS type");
					}
					
					if (defTag.matches("\\.\\d+fake")) {
						fakeObjs.put(defTag, currStructUnion);
					} else {
						types.add(currStructUnion);
					}

					currStructUnion = null;
				} break;
				default: break;
				}
			} break;
			case 0x98: {
				long ovrLength = reader.readNextUnsignedInt(); // ovr_length
				long ovrId = reader.readNextUnsignedInt(); // ovr_id
				overlays.add(new SymOverlay(offset, ovrId, ovrLength));
			} break;
			case 0x9A: {
				currOverlay = offset;
			} break;
			case 0x9E: {
				readString(reader); // mangled name1
				readString(reader); // mangled name2
			} break;
			}
		}
	}
	
	public void applyOverlays(Program program, MessageLog log, TaskMonitor monitor) {
		monitor.initialize(overlays.size());
		monitor.setMessage("Creating overlays...");
		monitor.clearCanceled();
		
		Memory mem = program.getMemory();
		AddressSpace defAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		for (int i = 0; i < overlays.size(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			
			SymOverlay ovr = overlays.get(i);
			try {
				MemoryBlock block = mem.createUninitializedBlock(SymOverlay.getBlockName(ovr.getId()), defAddressSpace.getAddress(ovr.getOffset()), ovr.getSize(), true);
				block.setExecute(true);
				block.setRead(true);
				block.setWrite(true);
			} catch (LockException | DuplicateNameException | MemoryConflictException | AddressOverflowException | AddressOutOfBoundsException e) {
				log.appendException(e);
				return;
			}
			
			monitor.setProgress(i + 1);
		}
		
		monitor.setMessage("Overlays created.");
	}
	
	private void applyNames(final Map<SymDataTypeManagerType, DataTypeManager> mgrs, Program program, MessageLog log, TaskMonitor monitor) {
		monitor.initialize(names.size());
		monitor.setMessage("Applying SYM objects (names)...");
		monitor.clearCanceled();
		
		Map<String, SymObject> objs = new HashMap<>();
		
		for (SymName obj : names) {
			objs.put(obj.getName(), obj);
		}
		
		applySymbols(objs, "names", mgrs, program, log, monitor);
	}
	
	private void applyTypes(final Map<SymDataTypeManagerType, DataTypeManager> mgrs, Program program, MessageLog log, TaskMonitor monitor) {
		monitor.initialize(types.size());
		monitor.setMessage("Applying SYM objects (types)...");
		monitor.clearCanceled();
		
		Map<String, SymObject> objs = new HashMap<>();
		
		for (SymObject obj : types) {
			objs.put(((SymName)obj).getName(), obj);
		}
		
		applySymbols(objs, "types", mgrs, program, log, monitor);
	}
	
	private void applyNamesWithTypes(final Map<SymDataTypeManagerType, DataTypeManager> mgrs, Program program, MessageLog log, TaskMonitor monitor) {
		monitor.initialize(namesWithTypes.size());
		monitor.setMessage("Applying SYM objects (typed names)...");
		monitor.clearCanceled();
		
		Map<String, SymObject> objs = new HashMap<>();
		
		for (SymDefinition obj : namesWithTypes) {
			objs.put(obj.getName(), obj);
		}
		
		applySymbols(objs, "names", mgrs, program, log, monitor);
	}
	
	private void applyFuncs(final Map<SymDataTypeManagerType, DataTypeManager> mgrs, Program program, MessageLog log, TaskMonitor monitor) {
		monitor.initialize(funcs.size());
		monitor.setMessage("Applying SYM objects (functions)...");
		monitor.clearCanceled();
		
		Map<String, SymObject> objs = new HashMap<>();
		
		for (Map.Entry<String, SymFunc> obj : funcs.entrySet()) {
			objs.put(obj.getKey(), obj.getValue());
		}
		
		applySymbols(objs, "funcs", mgrs, program, log, monitor);
	}
	
	public void apply(Program program, MessageLog log, TaskMonitor monitor) {
		final Map<SymDataTypeManagerType, DataTypeManager> mgrs = new HashMap<>();
		mgrs.put(SymDataTypeManagerType.MGR_TYPE_MAIN, program.getDataTypeManager());
		mgrs.put(SymDataTypeManagerType.MGR_TYPE_PSYQ, PsxLoader.loadPsyqGdt(program, null));

		applyNames(mgrs, program, log, monitor);
		applyTypes(mgrs, program, log, monitor);
		applyNamesWithTypes(mgrs, program, log, monitor);
		applyFuncs(mgrs, program, log, monitor);
		
		removeUselessFake(mgrs, monitor);
	}
	
	private void applySymbols(Map<String, SymObject> objects, String type, final Map<SymDataTypeManagerType, DataTypeManager> mgrs, Program program, MessageLog log, TaskMonitor monitor) {
		int index = 0;
		boolean repeat = true;
		
		while (repeat) {
			repeat = false;
			
			Map<String, SymObject> tryAgainAdd = new HashMap<>();
			Set<String> tryAgainRem = new HashSet<>();
			
			for (Map.Entry<String, SymObject> obj : objects.entrySet()) {
				if (monitor.isCancelled()) {
					break;
				}
				
				String objName = obj.getKey();
				SymObject objValue = obj.getValue();
				
				if (objValue == null) {
					tryAgainRem.add(objName);
				} else {
					Address addr = objValue.getAddress(program);
					
					Set<String> structOrUnion = applySymbol(objValue, addr, mgrs, program, log);
					if (!structOrUnion.isEmpty()) {
						for (String ss : structOrUnion) {
							tryAgainAdd.put(ss, objects.get(ss));
						}
					} else {
						tryAgainRem.add(objName);
						repeat = true;
						
						index++;
					}
					
					monitor.setProgress(index + 1);
				}
			}
			
			for (Map.Entry<String, SymObject> add : tryAgainAdd.entrySet()) {
				objects.put(add.getKey(), add.getValue());
			}
			
			for (String rem : tryAgainRem) {
				objects.remove(rem);
			}
		}
		
		// dumpNotFound(notFound, type, log);
	}
	
	@SuppressWarnings("incomplete-switch")
	private static Set<String> applySymbol(SymObject obj, Address addr, final Map<SymDataTypeManagerType, DataTypeManager> mgrs, Program program, MessageLog log) {
		Set<String> result = new HashSet<>();
		
		SymbolTable st = program.getSymbolTable();
		DataTypeManager psyqMgr = mgrs.get(SymDataTypeManagerType.MGR_TYPE_PSYQ);
		DataTypeManager mainMgr = mgrs.get(SymDataTypeManagerType.MGR_TYPE_MAIN);

		if (obj instanceof SymFunc) {
			SymFunc sf = (SymFunc)obj;
			PsxLoader.setFunction(program, addr, sf.getName(), true, false, log);
			
			Set<String> structOrUnion = setFunctionArguments(mgrs, program, addr, sf, log);
			if (structOrUnion != null) {
				result.addAll(structOrUnion);
			} else {
				SetCommentCmd cmd = new SetCommentCmd(addr, CodeUnit.PLATE_COMMENT, String.format("File: %s", sf.getFileName()));
				cmd.applyTo(program);
			}
		} else if (obj instanceof SymTypedef) {
			SymTypedef tpdef = (SymTypedef)obj;
	
			DataType baseType = tpdef.getDataType(mgrs);
			
			if (baseType != null) {
				DataType tpdefType = new TypedefDataType(tpdef.getName(), baseType);
				
				if (SymDefinition.hasDataTypeName(psyqMgr, baseType.getName()) != null) {
					if (SymDefinition.hasDataTypeName(psyqMgr, tpdefType.getName()) != null) {
						return result;
					} else if (SymDefinition.hasDataTypeName(mainMgr, tpdefType.getName()) == null) {
						applyDataType(tpdefType, mainMgr);
					}
				} else if (SymDefinition.hasDataTypeName(mainMgr, baseType.getName()) == null) {
					applyDataType(tpdefType, mainMgr);
				}
			}
		} else if (obj instanceof SymStructUnionEnum) {
			SymStructUnionEnum ssu = (SymStructUnionEnum)obj;
			SymTypePrimitive type = ssu.getType();
			SymDefinition[] fields = ssu.getFields();
			
			switch (type) {
			case UNION: {
				DataType psyqType = SymDefinition.hasDataTypeName(psyqMgr, ssu.getName());
				DataType mainType = SymDefinition.hasDataTypeName(mainMgr, ssu.getName());
				
				if (psyqType != null) {
					return result;
				} else if (mainType == null || (mainType != null && ((Composite)mainType).getNumComponents() != fields.length)) {
					boolean skip = false;
					
					for (SymDefinition field : fields) {
						DataType dt = field.getDataType(mgrs);
						
						if (dt == null) {
							result.add(field.getBaseStructOrUnion());
							skip = true;
						}
					}
					
					if (!skip) {
						UnionDataType udt = new UnionDataType(ssu.getName());
						udt.setMinimumAlignment(4);
						
						Union uut = (Union)applyDataType(udt, mainMgr);
						
						for (SymDefinition field : fields) {
							DataType dt = field.getDataType(mgrs);
							uut.add(dt, field.getName(), null);
						}
					}
				}
			} break;
			case STRUCT: {
				DataType psyqType = SymDefinition.hasDataTypeName(psyqMgr, ssu.getName());
				DataType mainType = SymDefinition.hasDataTypeName(mainMgr, ssu.getName());

				if (psyqType != null) {
					return result;
				} else if ((mainType == null) || (mainType != null && ((Composite)mainType).getNumComponents() != fields.length)) {
					boolean skip = false;
					
					for (SymDefinition field : fields) {
						DataType dt = field.getDataType(mgrs);
						
						if (dt == null) {
							result.add(field.getBaseStructOrUnion());
							skip = true;
						}
					}
					
					if (!skip) {
						Structure sdt = new StructureDataType(ssu.getName(), 0);
						sdt.setMinimumAlignment(4);
						
						sdt = (Structure)applyDataType(sdt, mainMgr);
						
						for (SymDefinition field : fields) {
							DataType dt = field.getDataType(mgrs);
							sdt.add(dt, field.getName(), null);
						}
					}
				}
			} break;
			case ENUM: {
				EnumDataType edt = new EnumDataType(ssu.getName(), (int)ssu.getSize());
				
				for (SymDefinition field : fields) {
					edt.add(field.getName(), field.getOffset());
				}
				
				if (SymDefinition.hasDataTypeName(psyqMgr, ssu.getName()) != null) {
					return result;
				} else if (SymDefinition.hasDataTypeName(mainMgr, ssu.getName()) == null) {
					applyDataType(edt, mainMgr);
				}
			} break;
			}
		} else if (obj instanceof SymDefinition) {
			SymDefinition extStat = (SymDefinition)obj;
			
			DataType dt = extStat.getDataType(mgrs);
			
			if (dt != null) {
				try {
					st.createLabel(addr, extStat.getName(), SourceType.ANALYSIS);
					DataUtilities.createData(program, addr, dt, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				} catch (InvalidInputException | CodeUnitInsertionException e) {
					log.appendException(e);
				}
			}
		} else if (obj instanceof SymName) {
			SymName sn = (SymName)obj;
			try {
				st.createLabel(addr, sn.getName(), SourceType.ANALYSIS);
			} catch (InvalidInputException e) {
				if (!sn.getName().startsWith("MENU_")) {
					log.appendException(e);
				} else {
					try {
						st.createLabel(addr, String.format("_%s", sn.getName()), SourceType.ANALYSIS);
					} catch (InvalidInputException e1) {
						log.appendException(e);
					}
				}
			}
		} else {
			log.appendMsg(String.format("unkn type offset: 0x%08X", addr.getOffset()));
		}
		
		return result;
	}
	
	private static DataType applyDataType(DataType dt, DataTypeManager mgr) {
		int transId = mgr.startTransaction("Apply data type");
		DataType res = mgr.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		mgr.endTransaction(transId, true);
		return res;
	}
	
	private static Set<String> setFunctionArguments(final Map<SymDataTypeManagerType, DataTypeManager> mgrs, Program program, Address funcAddr, SymFunc funcDef, MessageLog log) {
		Set<String> result = new HashSet<>();
		
		try {
			Function func = program.getListing().getFunctionAt(funcAddr);
			
			if (func == null) {
				log.appendMsg(String.format("Cannot get function at: 0x%08X", funcAddr.getOffset()));
				return null;
			}
			
			DataType dt = funcDef.getDataType(mgrs);
			
			if (dt != null) {
				func.setReturnType(dt, SourceType.ANALYSIS);
			}
			
			boolean repeat = false;
			
			List<ParameterImpl> params = new ArrayList<>();
			SymDefinition[] args = funcDef.getArguments();
			
			for (int i = 0; i < args.length; ++i) {
				DataType argType = args[i].getDataType(mgrs);
				
				if (argType == null) {
					result.add(args[i].getBaseStructOrUnion());
					repeat = true;
				}
			}
			
			if (!repeat) {
				for (int i = 0; i < args.length; ++i) {
					DataType argType = args[i].getDataType(mgrs);
					params.add(new ParameterImpl(args[i].getName(), argType, program));
				}
			}
			
			if (!repeat) {
				func.updateFunction("__stdcall", null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
			}
		} catch (Exception e) {
			log.appendException(e);
		}
		
		return null;
	}
	
	private void removeUselessFake(final Map<SymDataTypeManagerType, DataTypeManager> mgrs, TaskMonitor monitor) {
		DataTypeManager mainMgr = mgrs.get(SymDataTypeManagerType.MGR_TYPE_MAIN);
		DataTypeManager psyqMgr = mgrs.get(SymDataTypeManagerType.MGR_TYPE_PSYQ);
		
		for (Map.Entry<String, SymStructUnionEnum> entry : fakeObjs.entrySet()) {
			DataType fake = SymDefinition.hasDataTypeName(mainMgr, entry.getKey());
			
			if (fake == null) {
				continue;
			}
			
			DataType def1 = SymDefinition.hasDataTypeName(mainMgr, entry.getValue().getName());
			DataType def = (def1 != null) ? def1 : SymDefinition.hasDataTypeName(psyqMgr, entry.getValue().getName());
			
			if (def != null) {
				mainMgr.remove(fake, monitor);
			}
		}
	}
	
	private static void dumpNotFound(final Set<String> notFound, String type, MessageLog log) {
		if (notFound.isEmpty()) {
			return;
		}
		
		boolean printed = false;
		for (String obj : notFound) {
			if (!printed) {
				log.appendMsg(String.format("The following %s haven't been found:", type));
				printed = true;
			}
			
			log.appendMsg(String.format("\t%s", obj));
		}
	}
	
	private static String readString(BinaryReader reader) throws IOException {
		return reader.readNextAsciiString(reader.readNextUnsignedByte());
	}
}

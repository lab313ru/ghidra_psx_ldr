//Imports a Psy-Q SYM file into the current program.
//
//The data types present within the SYM file will be filed under the "MND/" directory inside the data type manager.
//IMPORTANT: it is recommended to open a Psy-Q SDK data type file archive using the data type manager from the ghidra_psx_ldr plugin before running this script, so that the data types from the SDK are pulled from it instead of recreated from scratch.
//
//This script is based on the decompilation of DUMPSYM.EXE that can be found there: https://github.com/lab313ru/dumpsym_src/blob/master/main.c
//@author Jean-Baptiste Boric
//@category Import
//@keybinding
//@menupath Tools.Import Psy-Q SYM file…
//@toolbar

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.*;
import ghidra.app.util.bin.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ImportPSX_SYM extends GhidraScript {

	public static enum DefinitionClass {
		NULL(0x00),
		AUTO(0x01),
		EXT(0x02),
		STAT(0x03),
		REG(0x04),
		EXTDEF(0x05),
		LABEL(0x06),
		ULABEL(0x07),
		MOS(0x08),
		ARG(0x09),
		STRTAG(0x0A),
		MOU(0x0B),
		UNTAG(0x0C),
		TPDEF(0x0D),
		USTATIC(0x0E),
		ENTAG(0x0F),
		MOE(0x10),
		REGPARM(0x11),
		FIELD(0x12),
		BLOCK(0x13),
		FCN(0x14),
		EOS(0x66),
		FILE(0x67),
		LINE(0x68),
		ALIAS(0x69),
		HIDDEN(0x6A);

		private final int value;

		DefinitionClass(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static DefinitionClass fromValue(int value) {
			for (DefinitionClass def : values()) {
				if (def.getValue() == value) {
					return def;
				}
			}

			throw new IllegalArgumentException(String.format("Unknown type 0x%02x", value));
		}
	}

	public static class Chunk {
		public final long address;

		public Chunk(long address) {
			this.address = address;
		}
	}

	public static class ChunkFunctionStart extends Chunk {
		public final String file;
		public final long line;
		public final String name;

		public ChunkFunctionStart(long address, String file, long line, String name) {
			super(address);
			this.file = file;
			this.line = line;
			this.name = name;
		}
	}

	public static class ChunkFunctionEnd extends Chunk {
		public ChunkFunctionEnd(long address) {
			super(address);
		}
	}

	public static class ChunkDef extends Chunk {
		public final DefinitionClass clazz;
		public int type;
		public final long size;
		public final String name;
		public final List<Long> dimensions;
		public final String tag;

		public ChunkDef(long address, DefinitionClass clazz, int type, long size, String name) {
			super(address);
			this.clazz = clazz;
			this.type = type;
			this.size = size;
			this.name = name;
			this.dimensions = null;
			this.tag = null;
		}

		public ChunkDef(long address, DefinitionClass clazz, int type, long size, List<Long> dimensions, String tag,
				String name) {
			super(address);
			this.clazz = clazz;
			this.type = type;
			this.size = size;
			this.name = name;
			this.dimensions = dimensions;
			this.tag = tag;
		}
	}

	public static class ChunkSym extends Chunk {
		public final String name;

		public ChunkSym(long address, String name) {
			super(address);
			this.name = name;
		}
	}

	public static class ChunkSLDFilenameSet32 extends Chunk {
		public final long linenum;
		public final String filename;

		public ChunkSLDFilenameSet32(long address, long linenum, String filename) {
			super(address);
			this.linenum = linenum;
			this.filename = filename;
		}
	}

	public final class SYMLexer {
		public final List<Chunk> chunks = new ArrayList<>();

		private BinaryReader reader;

		public void processFile(File file) {
			try (FileInputStream fis = new FileInputStream(file)) {
				byte[] fileData = fis.readAllBytes();
				ByteArrayProvider provider = new ByteArrayProvider(fileData);
				reader = new BinaryReader(provider, true);

				parseHeader();
				while (reader.getPointerIndex() < reader.length()) {
					parseChunk();
				}
			} catch (Exception ex) {
				throw new RuntimeException(String.format("Parsing failure at offset %08x", reader.getPointerIndex()),
						ex);
			}
		}

		private void parseHeader() throws IOException {
			String sig = reader.readNextAsciiString(4);
			if (!sig.equals("MND\u0001")) {
				throw new IOException("Wrong MND signature");
			}

			reader.readNextByteArray(4); // target unit
		}

		private void parseChunk() throws IOException {
			long address = reader.readNextUnsignedInt();
			int tag = reader.readNextUnsignedByte();

			switch (tag) {
				case 0x01:
				case 0x02:
					parseTagSymbol(address);
					break;

				case 0x80:
					parseTagSLDInc(address);
					break;
				case 0x82:
					parseTagSLDInc8(address);
					break;
				case 0x84:
					parseTagSLDInc16(address);
					break;
				case 0x86:
					parseTagSLDSet32(address);
					break;
				case 0x88:
					parseTagSLDFilenameSet32(address);
					break;
				case 0x8A:
					parseTagSLDEnd(address);
					break;
				case 0x8C:
					parseTagFunctionStart(address);
					break;
				case 0x8E:
					parseTagFunctionEnd(address);
					break;
				case 0x90:
					parseTagBlockStart(address);
					break;
				case 0x92:
					parseTagBlockEnd(address);
					break;
				case 0x94:
					parseTagDef(address);
					break;
				case 0x96:
					parseTagDef2(address);
					break;
				default:
					throw new RuntimeException(String.format("Unsupported tag 0x%02x", tag));
			}
		}

		// Tag 0x00-0x7F
		private void parseTagSymbol(long address) throws IOException {
			String name = readPascalString();

			chunks.add(new ChunkSym(address, name));
		}

		// Tag 0x80
		private void parseTagSLDInc(long address) throws IOException {
		}

		// Tag 0x82
		private void parseTagSLDInc8(long address) throws IOException {
			reader.readNextUnsignedByte(); // line byte_add
		}

		// Tag 0x84
		private void parseTagSLDInc16(long address) throws IOException {
			reader.readNextUnsignedShort(); // line word_add
		}

		// Tag 0x86
		private void parseTagSLDSet32(long address) throws IOException {
			reader.readNextUnsignedInt(); // line line_num
		}

		// Tag 0x88
		private void parseTagSLDFilenameSet32(long address) throws IOException {
			long linenum = reader.readNextUnsignedInt(); // new line_num
			String filename = readPascalString(); // new file_name

			chunks.add(new ChunkSLDFilenameSet32(address, linenum, filename));
		}

		// Tag 0x8A
		private void parseTagSLDEnd(long address) throws IOException {
		}

		// Tag 0x8C
		private void parseTagFunctionStart(long address) throws IOException {
			int fp = reader.readNextUnsignedShort();
			long fsize = reader.readNextUnsignedInt();
			int retreg = reader.readNextUnsignedShort();
			long mask = reader.readNextUnsignedInt();
			long maskoffs = reader.readNextUnsignedInt();
			long line = reader.readNextUnsignedInt();
			String file = readPascalString();
			String name = readPascalString();

			chunks.add(new ChunkFunctionStart(address, file, line, name));
		}

		// Tag 0x8E
		private void parseTagFunctionEnd(long address) throws IOException {
			long endLine = reader.readNextUnsignedInt();

			chunks.add(new ChunkFunctionEnd(address));
		}

		// Tag 0x90
		private void parseTagBlockStart(long address) throws IOException {
			long startLine = reader.readNextUnsignedInt();
		}

		// Tag 0x92
		private void parseTagBlockEnd(long address) throws IOException {
			long endLine = reader.readNextUnsignedInt();
		}

		// Tag 0x94
		private void parseTagDef(long address) throws IOException {
			DefinitionClass clazz = DefinitionClass.fromValue(reader.readNextUnsignedShort());
			int type = reader.readNextUnsignedShort();
			long size = reader.readNextUnsignedInt();
			String name = readPascalString();

			chunks.add(new ChunkDef(address, clazz, type, size, name));
		}

		// Tag 0x96
		private void parseTagDef2(long address) throws IOException {
			DefinitionClass clazz = DefinitionClass.fromValue(reader.readNextUnsignedShort());
			int type = reader.readNextUnsignedShort();
			long size = reader.readNextUnsignedInt();
			int dimCount = reader.readNextUnsignedShort();
			List<Long> dimensions = new ArrayList<>();
			for (int i = 0; i < dimCount; i++) {
				dimensions.add(reader.readNextUnsignedInt());
			}
			String tag = readPascalString();
			String name = readPascalString();

			chunks.add(new ChunkDef(address, clazz, type, size, dimensions, tag, name));
		}

		private String readPascalString() throws IOException {
			return reader.readNextAsciiString(reader.readNextUnsignedByte());
		}
	}

	public class SYMParser {
		public static abstract class Type {
			public final ChunkDef definition;

			public Type(ChunkDef definition) {
				this.definition = definition;
			}
		}

		public static class TypeTag extends Type {
			public final List<ChunkDef> children = new ArrayList<>();

			public TypeTag(ChunkDef definition) {
				super(definition);
			}
		}

		public static class TypeDef extends Type {
			public TypeDef(ChunkDef definition) {
				super(definition);
			}
		}

		public interface Label {
		}

		public static class LabelFunction implements Label {
			public final ChunkDef definition;
			public ChunkFunctionStart fnStart;
			public ChunkFunctionEnd fnEnd;
			public final List<ChunkDef> parameters = new ArrayList<>();

			public LabelFunction(ChunkDef definition) {
				this.definition = definition;
			}
		}

		public static class LabelData implements Label {
			public final Chunk definition;

			public LabelData(Chunk definition) {
				this.definition = definition;
			}
		}

		public ChunkSLDFilenameSet32 sldFile;
		public List<Type> types = new ArrayList<>();
		public Map<Long, Label> namespaceLabels = new TreeMap<>();

		private TypeTag currentTag;
		private LabelFunction currentFunction;

		public void processChunk(Chunk chunk) {
			if (chunk instanceof ChunkSLDFilenameSet32) {
				processSLDFilenameSet32((ChunkSLDFilenameSet32) chunk);
			} else if (chunk instanceof ChunkFunctionStart) {
				processFunctionStart((ChunkFunctionStart) chunk);
			} else if (chunk instanceof ChunkFunctionEnd) {
				processFunctionEnd((ChunkFunctionEnd) chunk);
			} else if (chunk instanceof ChunkDef) {
				processDef((ChunkDef) chunk);
			} else if (chunk instanceof ChunkSym) {
				processSym((ChunkSym) chunk);
			} else {
				throw new RuntimeException("Unknown chunk class " + chunk.getClass().getName());
			}
		}

		private void processSLDFilenameSet32(ChunkSLDFilenameSet32 chunk) {
			sldFile = chunk;
		}

		private void processFunctionStart(ChunkFunctionStart fs) {
			currentFunction = (LabelFunction) namespaceLabels.get(fs.address);
			currentFunction.fnStart = fs;
		}

		private void processFunctionEnd(ChunkFunctionEnd fe) {
			currentFunction.fnEnd = fe;
			currentFunction = null;
		}

		private void processDef(ChunkDef def) {
			switch (def.clazz) {
				case ENTAG:
				case STRTAG:
				case UNTAG: {
					currentTag = new TypeTag(def);
					break;
				}

				case FIELD:
				case MOE:
				case MOS:
				case MOU: {
					currentTag.children.add(def);
					break;
				}

				case EOS: {
					types.add(currentTag);
					currentTag = null;
					break;
				}

				case TPDEF: {
					types.add(new TypeDef(def));
					break;
				}

				case STAT:
				case EXT: {
					if ((def.type & 0x30) == 0x20) {
						namespaceLabels.put(def.address, new LabelFunction(def));
					} else {
						namespaceLabels.put(def.address, new LabelData(def));
					}
					break;
				}

				case REGPARM: {
					currentFunction.parameters.add(def);
					break;
				}

				// TODO: support stack variable definitions
				case ALIAS:
				case ARG:
				case AUTO:
				case BLOCK:
				case EXTDEF:
				case FCN:
				case FILE:
				case HIDDEN:
				case LABEL:
				case LINE:
				case NULL:
				case REG:
				case ULABEL:
				case USTATIC:
					break;
			}
		}

		private void processSym(ChunkSym sym) {
			namespaceLabels.put(sym.address, new LabelData(sym));
		}

		private Iterator<Type> typesIterator;
		private Map<String, TypeTag> tagTypeTags = new HashMap<>();
		private Map<String, DataType> tagDataTypes = new HashMap<>();

		public void importToProgram() {
			typesIterator = types.iterator();
			processTypes();
			processLabels();
		}

		private void processTypes() {
			while (typesIterator.hasNext()) {
				Type type = typesIterator.next();

				if (type instanceof TypeDef) {
					processTypeDef((TypeDef) type);
				} else if (type instanceof TypeTag) {
					tagTypeTags.put(type.definition.name, (TypeTag) type);
					if (!isFake(type.definition.name)) {
						processTypeTag(type.definition.name, (TypeTag) type);
					}
				} else {
					throw new RuntimeException("Unknown type " + type.getClass().getSimpleName());
				}
			}
		}

		private DataType getDataTypeFromDef(ChunkDef def) {
			if (def.tag != null && !def.tag.isBlank()) {
				//TODO: check that the data types are indeed equal instead of just checking the data type names
				return findDataTypeByTag(def);
			} else {
				return getDataTypeFromBasicDefinition(def);
			}
		}

		private TypeTag findTypeTagByName(String name) {
			TypeTag typeTag = tagTypeTags.get(name);
			if (typeTag == null) {
				processTypes();

				typeTag = tagTypeTags.get(name);
				if (typeTag == null) {
					throw new RuntimeException("Can't find type tag " + name);
				}
			}

			return typeTag;
		}

		private DataType findDataTypeByTag(ChunkDef def) {
			DataType dataType = findDataTypeByName(def.tag, DataType.class);
			if (dataType == null) {
				dataType = tagDataTypes.get(def.tag);

				if (dataType == null) {
					processTypes();
					dataType = findDataTypeByName(def.tag, DataType.class);

					if (dataType == null) {
						dataType = tagDataTypes.get(def.tag);
						if (dataType == null) {
							TypeTag typeTag = tagTypeTags.get(def.tag);
							if (typeTag != null) {
								// Anonymous tag, instanciate it with fake name anyway.
								String name = String.format("_%s_%d", def.tag.substring(1), uniqueAnonymousCount++);
								dataType = processTypeTag(name, typeTag);
							} else {
								throw new RuntimeException("Can't find data type tag " + def.tag);
							}
						}
					}
				}
			}

			return applyExtendedTypeToDataType(dataType, def);
		}

		private void processTypeDef(TypeDef typeDef) {
			DataType dataType = findDataTypeByName(typeDef.definition.name, DataType.class);
			if (dataType != null) {
				if (typeDef.definition.tag != null && isFake(typeDef.definition.tag)) {
					tagDataTypes.put(typeDef.definition.tag, dataType);
				}
				return;
			}

			if (typeDef.definition.tag == null || typeDef.definition.tag.isBlank()) {
				dataType = getDataTypeFromBasicDefinition(typeDef.definition);
				registerDataType(new TypedefDataType(new CategoryPath("/MND"), typeDef.definition.name, dataType));
				writer.println("Defined typedef " + typeDef.definition.name);
			} else {
				dataType = findDataTypeByName(typeDef.definition.tag, DataType.class);
				if (dataType != null) {
					registerDataType(new TypedefDataType(new CategoryPath("/MND"), typeDef.definition.name, dataType));
					writer.println("Defined typedef " + typeDef.definition.name);
				} else {
					// Typedef of anonymous tag, instanciate it.
					dataType = processTypeTag(typeDef.definition.name, findTypeTagByName(typeDef.definition.tag));
					if (isFake(typeDef.definition.tag)) {
						tagDataTypes.put(typeDef.definition.tag, dataType);
					}
				}
			}
		}

		private DataType processTypeTag(String name, TypeTag typeTag) {
			DataType dataType = findDataTypeByName(name, DataType.class);
			if (dataType != null) {
				if (typeTag.definition.tag != null && isFake(typeTag.definition.tag)) {
					tagDataTypes.put(typeTag.definition.tag, dataType);
				}
				return dataType;
			}

			if (typeTag.definition.clazz == DefinitionClass.ENTAG) {
				ghidra.program.model.data.Enum enum_ = new EnumDataType(new CategoryPath("/MND"), name,
						(int) typeTag.definition.size);
				registerDataType(enum_);

				for (ChunkDef def : typeTag.children) {
					enum_.add(def.name, def.address);
				}

				writer.println("Defined enum " + name);
				return enum_;
			} else if (typeTag.definition.clazz == DefinitionClass.STRTAG) {
				Structure struct = new StructureDataType(new CategoryPath("/MND"), name, 0,
						getProgramDataTypeManager());
				struct.setToDefaultPacking();
				registerDataType(struct);

				for (ChunkDef def : typeTag.children) {
					DataType child;

					if (def.clazz == DefinitionClass.FIELD) {
						try {
							child = getDataTypeFromBasicDefinition(def);
							struct.addBitField(child, (int) def.size, def.name, null);
						} catch (InvalidDataTypeException ex) {
							throw new RuntimeException(ex);
						}
					} else {
						child = getDataTypeFromDef(def);
						struct.insertAtOffset((int) def.address, child, child.getLength(), def.name, null);
					}
				}

				struct.repack();
				if (struct.getLength() != typeTag.definition.size) {
					writer.println("Structure " + name + " doesn't match declared size " + typeTag.definition.size);
				}
				// Re-register to refresh struct inside DataTypeManager. Not sure why it is
				// necessary.
				registerDataType(struct);
				writer.println("Defined struct " + name);
				return struct;
			} else if (typeTag.definition.clazz == DefinitionClass.UNTAG) {
				Union union = new UnionDataType(new CategoryPath("/MND"), name, getProgramDataTypeManager());
				union.setToDefaultPacking();
				registerDataType(union);

				for (ChunkDef def : typeTag.children) {
					DataType child = getDataTypeFromDef(def);

					union.add(child, (int) def.size, def.name, null);
				}

				union.repack();
				if (union.getLength() != typeTag.definition.size) {
					writer.println("Union " + name + " doesn't match declared size " + typeTag.definition.size);
				}
				writer.println("Defined union " + name);
				return union;
			} else {
				throw new RuntimeException(
						"Unknown type tag kind " + typeTag.definition.clazz.getClass().getSimpleName());
			}
		}

		private void processLabels() {
			for (Label label : namespaceLabels.values()) {
				if (label instanceof LabelFunction) {
					processFunction((LabelFunction) label);
				} else if (label instanceof LabelData) {
					processData((LabelData) label);
				} else {
					throw new RuntimeException("Unknown label type " + label.getClass().getSimpleName());
				}
			}
		}

		private void processFunction(LabelFunction labelFunction) {
			try {
				String name = labelFunction.definition.name;
				Address start = getAddress(labelFunction.fnStart.address);
				Address end = getAddress(labelFunction.fnEnd.address - 1);
				AddressSetView body = addressFactory.getAddressSet(start, end);
				Function func = functionManager.getFunctionAt(start);
				if (func == null) {
					func = functionManager.createFunction(name, start, body, SourceType.IMPORTED);
				} else {
					func.setName(name, SourceType.IMPORTED);
					func.setBody(body);
				}

				int previousType = labelFunction.definition.type;
				labelFunction.definition.type = stripExtendedType(previousType);
				DataType returnType = getDataTypeFromDef(labelFunction.definition);
				labelFunction.definition.type = previousType;
				func.setReturnType(returnType, SourceType.IMPORTED);

				List<ParameterImpl> parameters = labelFunction.parameters.stream().map(chunk -> {
					try {
						return new ParameterImpl(chunk.name, getDataTypeFromDef(chunk), currentProgram);
					} catch (Exception ex) {
						throw new RuntimeException(ex);
					}
				}).toList();
				func.replaceParameters(parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
						SourceType.IMPORTED);

				writer.println(String.format("0x%08x> Processed function %s", labelFunction.definition.address, name));
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private void processData(LabelData labelData) {
			Address start = getAddress(labelData.definition.address);

			if (labelData.definition instanceof ChunkSym) {
				ChunkSym sym = (ChunkSym) labelData.definition;

				try {
					symbolTable.createLabel(start, sym.name, SourceType.IMPORTED);

					writer.println(String.format("0x%08x> Processed label %s", labelData.definition.address, sym.name));
				} catch (Exception ex) {
					throw new RuntimeException(ex);
				}
			} else if (labelData.definition instanceof ChunkDef) {
				ChunkDef def = (ChunkDef) labelData.definition;
				DataType dataType = getDataTypeFromDef(def);

				try {
					listing.clearCodeUnits(start, start.add(dataType.getLength() - 1), false);
					listing.createData(start, dataType);
					symbolTable.createLabel(start, def.name, SourceType.IMPORTED);

					writer.println(String.format("0x%08x> Processed data %s", labelData.definition.address, def.name));
				} catch (Exception ex) {
					throw new RuntimeException(ex);
				}
			} else {
				throw new RuntimeException("Unknown chunk type " + labelData.definition.getClass().getSimpleName());
			}
		}
	}

	private SYMLexer symLexer;
	private SYMParser symParser;

	private Listing listing;
	private SymbolTable symbolTable;
	private DataTypeArchiveService dataTypeArchiveService;
	private AddressFactory addressFactory;
	private FunctionManager functionManager;
	private DataTypeManager dataTypeManagers[];

	private int uniqueAnonymousCount = 0;

	public void run() throws Exception {
		listing = currentProgram.getListing();
		symbolTable = currentProgram.getSymbolTable();
		dataTypeArchiveService = state.getTool().getService(DataTypeArchiveService.class);
		dataTypeManagers = dataTypeArchiveService.getDataTypeManagers();
		addressFactory = currentProgram.getAddressFactory();
		functionManager = currentProgram.getFunctionManager();

		File file = askFile("Please specify a SYM file to import", "Import");

		writer.println("Lexing SYM file...");
		symLexer = new SYMLexer();
		symLexer.processFile(file);
		writer.println("Finished lexing SYM file.");

		writer.println("Parsing SYM file...");
		symParser = new SYMParser();
		for (Chunk chunk : symLexer.chunks) {
			symParser.processChunk(chunk);
		}
		writer.println("Finished parsing SYM file.");

		String filename;
		if (symParser.sldFile == null || symParser.sldFile.filename.isEmpty()) {
			filename = file.getAbsolutePath();
		}
		else {
			filename = symParser.sldFile.filename;
		}

		writer.println("Importing SYM file (" + filename + ")...");
		symParser.importToProgram();
	}

	protected BuiltInDataTypeManager getBuiltInDataTypeManager() {
		for (DataTypeManager dtm : dataTypeManagers) {
			if (dtm instanceof BuiltInDataTypeManager) {
				return (BuiltInDataTypeManager) dtm;
			}
		}

		throw new RuntimeException("Couldn't find built-in data type manager");
	}

	protected DataTypeManager getProgramDataTypeManager() {
		return currentProgram.getDataTypeManager();
	}

	protected void registerDataType(DataType dataType) {
		getProgramDataTypeManager().addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	protected static Class<?> getBaseGhidraClassFromType(int type) {
		switch (type & 0xF) {
			case 8:
				return ghidra.program.model.data.Structure.class;
			case 9:
				return ghidra.program.model.data.Union.class;
			case 10:
				return ghidra.program.model.data.Enum.class;
			default:
				return null;
		}
	}

	protected static Class<?> getGhidraClassFromDefinitionClass(DefinitionClass clazz) {
		switch (clazz) {
			case STRTAG:
				return ghidra.program.model.data.Structure.class;
			case UNTAG:
				return ghidra.program.model.data.Union.class;
			case ENTAG:
				return ghidra.program.model.data.Enum.class;
			default:
				return null;
		}
	}

	protected Address getAddress(long address) {
		return addressFactory.getDefaultAddressSpace().getAddress(address);
	}

	protected static <T> Iterable<T> getIterableFromIterator(Iterator<T> iterator) {
		return () -> iterator;
	}

	protected DataType findDataTypeByName(String name, Class<?> clazz) {
		for (DataTypeManager dtm : dataTypeManagers) {
			for (DataType dataType : getIterableFromIterator(dtm.getAllDataTypes())) {
				if (dataType.getName().equals(name) && clazz.isAssignableFrom(dataType.getClass())) {
					return dataType;
				}
			}
		}

		return null;
	}

	protected DataType getDataTypeFromBasicDefinition(ChunkDef def) {
		DataType dataType;
		switch (def.type & 0xF) {
			case 1:
				dataType = getBuiltInDataTypeManager().getDataType("/void");
				break;
			case 2:
				dataType = getBuiltInDataTypeManager().getDataType("/char");
				break;
			case 3:
				dataType = getBuiltInDataTypeManager().getDataType("/short");
				break;
			case 4:
				dataType = getBuiltInDataTypeManager().getDataType("/int");
				break;
			case 5:
				dataType = getBuiltInDataTypeManager().getDataType("/long");
				break;
			case 6:
				dataType = getBuiltInDataTypeManager().getDataType("/float");
				break;
			case 7:
				dataType = getBuiltInDataTypeManager().getDataType("/double");
				break;
			case 12:
				dataType = getBuiltInDataTypeManager().getDataType("/uchar");
				break;
			case 13:
				dataType = getBuiltInDataTypeManager().getDataType("/ushort");
				break;
			case 14:
				dataType = getBuiltInDataTypeManager().getDataType("/uint");
				break;
			case 15:
				dataType = getBuiltInDataTypeManager().getDataType("/ulong");
				break;
			default: {
				throw new RuntimeException("No built-in data type found for " + def.name);
			}
		}

		return applyExtendedTypeToDataType(dataType, def);
	}

	protected DataType applyExtendedTypeToDataType(DataType dataType, ChunkDef def) {
		int aryCount = 0;
		int type = def.type;

		while ((type & 0xFFF0) != 0 && (type & 0xC000) == 0) {
			type = nextExtendedType(type);
		}

		while ((type & 0xFFF0) != 0) {
			switch ((type >> 14) & 3) {
				case 1: {
					if (dataType.getName().equals("void")) {
						dataType = getBuiltInDataTypeManager().getDataType("/pointer");
					} else {
						dataType = new PointerDataType(dataType, getProgramDataTypeManager());
					}
					break;
				}
				case 2: {
					// TODO: properly deal with function pointers
					dataType = getBuiltInDataTypeManager().getDataType("/pointer");
					break;
				}
				case 3: {
					dataType = new ArrayDataType(dataType, def.dimensions.get(aryCount).intValue(),
							dataType.getLength());
					aryCount++;
					break;
				}
				default:
					throw new RuntimeException("Unknown extended type information for " + def.name);
			}

			type = nextExtendedType(type);
		}

		return dataType;
	}

	private static int nextExtendedType(int type) {
		return (((type & 0xFFF0) << 2) | (type & 0xF)) & 0xFFFF;
	}

	private static int stripExtendedType(int type) {
		return ((type >> 2) & 0xFFF0) + (type & 0xF);
	}

	private static boolean isFake(String string) {
		return string.startsWith(".") && string.endsWith("fake");
	}
}

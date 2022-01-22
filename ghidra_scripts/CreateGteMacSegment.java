//
//@author DrMefistO
//@category PSX GTE
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class CreateGteMacSegment extends GhidraScript {

	public static final class PsxGteMacro {
		private final String name;
		private final String[] args;
		
		public PsxGteMacro(final String name, final String[] args) {
			this.name = name;
			this.args = args.clone();
		}
		
		public String getName() {
			return name;
		}
		
		public String[] getArgs() {
			return args;
		}
	}
	
	@Override
	protected void run() throws Exception {
		MessageLog log = new MessageLog();
		DataTypeManager mgr = loadPsyqGdt(currentProgram, log, true);
		addGteMacroSpace(this, currentProgram, mgr, log);
	}
	
	private static DataTypeManagerService getDataTypeManagerService(Program program) {
		return AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();
	}
	
	private static void closePsyqDataTypeArchives(Program program, String gdtName) {
		DataTypeManagerService srv = getDataTypeManagerService(program);
		DataTypeManager[] mgrs = srv.getDataTypeManagers();

		for (DataTypeManager mgr : mgrs) {
			if (!mgr.getName().contains(gdtName)) {
				srv.closeArchive(mgr);
			}
		}
	}
	
	private static String getProgramPsyqVersion(Program program) {
		Options opts = program.getOptions(Program.PROGRAM_INFO);
		return opts.getString("PsyQ Version", "").replace(".", "");
	}
	
	private static DataTypeManager loadPsyqGdt(Program program, MessageLog log, boolean closeOthers) {
		String gdtName = String.format("psyq%s", getProgramPsyqVersion(program));
		
		if (closeOthers) {
			closePsyqDataTypeArchives(program, gdtName);
		}
		return loadPsyqArchive(program, gdtName, TaskMonitor.DUMMY, log);
	}
	
	private static DataTypeManager loadPsyqArchive(Program program, String gdtName, TaskMonitor monitor, MessageLog log) {
		DataTypeManagerService srv = getDataTypeManagerService(program);
		
		if (gdtName.isEmpty()) {
			return null;
		}
		
		try {
			DataTypeManager[] mgrs = srv.getDataTypeManagers();
			
			for (DataTypeManager mgr : mgrs) {
				if (mgr.getName().equals(gdtName) || mgr.getName().startsWith(gdtName)) {
					return mgr;
				}
			}
			
			DataTypeManager mgr = srv.openDataTypeArchive(gdtName);
			
			if (mgr == null) {
				throw new IOException(String.format("Cannot find \"%s\" data type archive!", gdtName));
			}
			
			return mgr;
		} catch (IOException | DuplicateIdException e) {
			log.appendException(e);
		}
		
		return null;
	}
	
	private static JsonArray jsonArrayFromFile(final String file) throws IOException {
		if (file == null) {
			return null;
		}
		
		final byte[] bytes = Files.readAllBytes(Path.of(file));
		final String json = new String(bytes, "UTF8");
		
		final JsonElement tokens = JsonParser.parseString(json);
		return tokens.getAsJsonArray();
	}
	
	private static List<CreateGteMacSegment.PsxGteMacro> preloadGteMacroses(GhidraScript script, Program program) throws IOException, CancelledException {
		File gteMacroFile = script.askFile("Please, select gte_macro.json", "OK");
		JsonArray gteMacroses = jsonArrayFromFile(gteMacroFile.getAbsolutePath());
		
		List<CreateGteMacSegment.PsxGteMacro> macroses = new ArrayList<>();
		
		for (final var gteMacro : gteMacroses) {
			final JsonObject obj = gteMacro.getAsJsonObject();
			
			final String name = obj.get("name").getAsString();
			final JsonArray argsJson = obj.getAsJsonArray("args");
			
			List<String> args = new ArrayList<>();
			
			for (final var arg : argsJson) {
				args.add(arg.getAsString());
			}
			
			macroses.add(new CreateGteMacSegment.PsxGteMacro(name, args.toArray(String[]::new)));
		}
		
		return macroses;
	}
	
	private static void addGteMacroSpace(GhidraScript script, Program program, DataTypeManager mgr, MessageLog log) throws InvalidInputException, DuplicateNameException, LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, CodeUnitInsertionException {
		List<PsxGteMacro> macroses;
		try {
			macroses = preloadGteMacroses(script, program);
		} catch (CancelledException | IOException e) {
			e.printStackTrace();
			return;
		}
		
		Listing listing = program.getListing();
		AddressSpace defSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address start = defSpace.getAddress(0x20000000L);
		
		MemoryBlock gteMacBlock = program.getMemory().getBlock("GTEMAC"); 
		if (gteMacBlock != null) {
			if (macroses.size() * 4 == gteMacBlock.getSize()) {
				return;
			}
			program.getMemory().removeBlock(gteMacBlock, TaskMonitor.DUMMY);
		}
		
		createUnitializedSegment(program, "GTEMAC", start, macroses.size() * 4, false, true, log);
		
		Pattern pat = Pattern.compile("^.+?\\[(\\d+)\\]$");
		
		Map<String, DataType> dtReady = new HashMap<>();
		
		for (int i = 0; i < macroses.size(); ++i) {
			final var macro = macroses.get(i);
			final Address addr = start.add(i * 4);
			CreateFunctionCmd cmd = new CreateFunctionCmd(macro.getName(), addr, null, SourceType.IMPORTED);
			cmd.applyTo(program);
			
			Function func = listing.getFunctionAt(addr);
			func.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
			func.setCustomVariableStorage(true);
			
			List<ParameterImpl> params = new ArrayList<>();

			final String[] args = macro.getArgs();
			for (int j = 0; j < args.length; ++j) {
				String arg = args[j];
				
				DataType dt = stringToDataType(mgr, arg, pat, dtReady);

				params.add(new ParameterImpl(String.format("r%d", j), dt, program.getRegister(String.format("gte%d", j)), program, SourceType.USER_DEFINED));
			}
			
			func.updateFunction("__gtemacro", null,
					FunctionUpdateType.CUSTOM_STORAGE,
					true, SourceType.IMPORTED, params.toArray(ParameterImpl[]::new));
			
			DataUtilities.createData(program, addr, new ArrayDataType(ByteDataType.dataType, 4, -1), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
	}
	
	private static DataType stringToDataType(DataTypeManager mgr, String type, Pattern pat, Map<String, DataType> cache) {
		DataType dt;
		
		if (cache.containsKey(type)) {
			dt = cache.get(type);
		} else {
			List<DataType> allDts = new ArrayList<>();
			mgr.findDataTypes(type, allDts);
			
			if (allDts.size() == 0) {
				String baseType = type;
				boolean isPtr = type.contains("*");
				boolean isArray = !isPtr && (type.contains("["));
				int arrCount = 0;
				
				if (isPtr) {
					type = type.replaceAll("(?:[ \\t]+)?\\*", "");
				} else if (isArray) {
					Matcher mat = pat.matcher(type);
					
					if (mat.matches()) {
						arrCount = Integer.parseInt(mat.group(1));
						type = type.replaceAll("(?:[ \\t]+)?\\[\\d+\\]", "");
					}
				}
				
				dt = stringToDataType(mgr, type, pat, cache);
				type = baseType;
				
				if (isPtr) {
					dt = new PointerDataType(dt);
				} else if (isArray) {
					dt = new ArrayDataType(dt, arrCount, -1);
				}
			} else {
				dt = allDts.get(0);
			}
			
			cache.put(type, dt);
		}
		
		return dt;
	}
	
	private static void createUnitializedSegment(Program program, String name, Address address, long size, boolean write, boolean execute, MessageLog log) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException {
		MemoryBlock block = program.getMemory().createUninitializedBlock(name, address, size, false);
		block.setRead(true);
		block.setWrite(write);
		block.setExecute(execute);
	}
}

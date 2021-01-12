package psyq;

//import java.io.BufferedWriter;
//import java.io.File;
//import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.File;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.stl.Pair;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class SigApplier {
	private final List<PsyqSig> signatures;
	private final String shortLibName;
	private final String gameId;
	private final boolean sequential;
	private final boolean onlyFirst;
	private final float minEntropy;
	
	public SigApplier(final String gameId, final String libJsonPath, final String patchesFile, boolean sequential, boolean onlyFirst, float minEntropy, TaskMonitor monitor) throws IOException {
		this.gameId = gameId.replace("_", "").replace(".", "");
		this.sequential = sequential;
		this.onlyFirst = onlyFirst;
		this.minEntropy = minEntropy;
		
		final File libJsonFile = new File(libJsonPath);
		this.shortLibName = libJsonFile.getName().replace(".json", "");
		
		final JsonArray root = jsonArrayFromFile(libJsonPath);
		final JsonArray patches = jsonArrayFromFile(patchesFile);
		
		final String psyLibVersion = libJsonFile.getParentFile().getName();
		final JsonArray patchesObj = findGamePatches(patches, psyLibVersion);
		
		signatures = new ArrayList<>();
//		StringBuilder sb = new StringBuilder();
		
		for (var item : root) {
			final JsonObject itemObj = item.getAsJsonObject();
			final PsyqSig sig = PsyqSig.fromJsonToken(itemObj, patchesObj);
			
//			sb.append(String.format("%s/%s: %.2f", this.file, sig.getName(), sig.getEntropy()));
//			sb.append("\n");
			
			signatures.add(sig);
		}
		
//		try (BufferedWriter writer = new BufferedWriter(new FileWriter(new File(file + ".log")))) {
//		    writer.write(sb.toString());
//		}
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
	
	private JsonArray findGamePatches(final JsonArray patches, final String version) {
		if (patches == null) {
			return null;
		}
		
		for (var patch : patches) {
			final JsonObject patchObj = patch.getAsJsonObject();
			
			final String patchGameName = patchObj.get("name").getAsString().replace("_", "").replace(".", "");
			
			if (!patchGameName.equalsIgnoreCase(gameId)) {
				continue;
			}
			
			final JsonArray libs = patchObj.getAsJsonArray("libs");
			
			for (var lib : libs) {
				final JsonObject libObj = lib.getAsJsonObject();
				
				final String patchLibName = libObj.get("name").getAsString();
				
				if (!patchLibName.equalsIgnoreCase(shortLibName)) {
					continue;
				}
				
				final JsonArray patchLibVersions = libObj.get("versions").getAsJsonArray();
				
				for (var libVer : patchLibVersions) {
					final String patchLibVer = libVer.getAsString().replace(".", "");
					
					if (!patchLibVer.equals(version)) {
						continue;
					}
					
					return libObj.getAsJsonArray("objs");
				}
			}
		}
		
		return null;
	}
	
	public List<PsyqSig> getSignatures() {
		return signatures;
	}
	
	public int applySignatures(Program program, Address startAddr, Address endAddr, TaskMonitor monitor, MessageLog log) {
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		
		int appliedObjs = 0;
		int totalObjs = signatures.size();
		long prevObjAddr = 0L;
		
		monitor.initialize(totalObjs);
		monitor.setMessage("Applying obj symbols...");
		monitor.clearCanceled();
		
		Map<String, Pair<Long, Float>> objsList = new HashMap<>();
		
		for (final PsyqSig sig : signatures) {
			if (monitor.isCancelled()) {
				break;
			}
			
			if ((sig.isApplied() && onlyFirst) || sig.getEntropy() < minEntropy) {
				continue;
			}
			
			final MaskedBytes bytes = sig.getSig();
			final List<Pair<String, Integer>> labels = sig.getLabels();
			
			Address searchAddr = sequential ? fpa.toAddr(Math.max(startAddr.getOffset(), prevObjAddr)) : startAddr;
			boolean applied = false;
			boolean objectUsed = false;
			
			while (!monitor.isCancelled() && searchAddr.compareTo(endAddr) == -1 && (!applied || !onlyFirst)) {
				final Address addr = program.getMemory().findBytes(searchAddr, endAddr, bytes.getBytes(), bytes.getMasks(), true, monitor);
				
				if (addr == null) {
					monitor.incrementProgress(1);
					break;
				}
				
				if (sequential) {
					prevObjAddr = Math.max(addr.getOffset(), prevObjAddr);
				}
				
				objsList.put(sig.getName(), new Pair<>(addr.getOffset(), sig.getEntropy()));
				
				for (var lb : labels) {
					final String lbName = lb.first;
					final long lbOffset = lb.second;
					
					final Address lbAddr = addr.add(lbOffset);
					final MemoryBlock block = memory.getBlock(lbAddr);
					
					if (block == null) {
						continue;
					}
					
					if (block.isExecute() && block.isInitialized()) {
						if (listing.getInstructionAt(lbAddr) == null) {
							DisassembleCommand disCmd = new DisassembleCommand(new AddressSet(lbAddr), null);
							disCmd.applyTo(program);
						}
						
						boolean isFunction = !lbName.startsWith("loc_");
						final String newName = String.format("%s_", sig.getName().replace(".", "_"));
						final String newLbName = lbName.replace("text_", newName).replace("loc_", newName);
						setFunction(program, fpa, lbAddr, newLbName, isFunction, false, log);
						
						monitor.setMessage(String.format("Symbol %s at 0x%08X", newLbName, lbAddr.getOffset()));
						
						applied = true;
					}
				}
				
				searchAddr = addr.add(4);
				monitor.incrementProgress(1);
			}
			
			sig.setApplied(applied);
			
			if (applied && !objectUsed) {
				appliedObjs += 1;
				objectUsed = true;
			}
		}
		
		if (appliedObjs > 0) {
			log.appendMsg(String.format("Applied OBJs for %s: %d/%d:", shortLibName, appliedObjs, totalObjs));
			
			for (var objName : objsList.entrySet()) {
				var val = objName.getValue();
				log.appendMsg(String.format("\t0x%08X: %s, %.02f entropy", val.first, objName.getKey(), val.second));
			}
		}
		
		return appliedObjs;
	}
	
	private static void disasmInstruction(Program program, Address address) {
		DisassembleCommand cmd = new DisassembleCommand(address, null, true);
		cmd.applyTo(program, TaskMonitor.DUMMY);
	}
	
	public static void setFunction(Program program, FlatProgramAPI fpa, Address address, String name, boolean isFunction, boolean isEntryPoint, MessageLog log) {
		try {
			if (fpa.getInstructionAt(address) == null)
				disasmInstruction(program, address);
			
			if (isFunction) {
				fpa.createFunction(address, name);
			}
			if (isEntryPoint) {
				fpa.addEntryPoint(address);
			}
			
			Symbol[] existing = program.getSymbolTable().getSymbols(address);
			if (isFunction && existing.length > 0) {
				for (var sym : existing) {
					if (sym.getSource() == SourceType.USER_DEFINED) {
						return;
					}
				}
			}
			
			program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
			e.printStackTrace();
		}
	}
}

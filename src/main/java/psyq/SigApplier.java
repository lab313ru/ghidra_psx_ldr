package psyq;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

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
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class SigApplier {
	private final Map<String, PsyqSig> signatures;
	private final String file;
	
	public SigApplier(String file, TaskMonitor monitor) throws IOException {
		this.file = Path.of(file).getFileName().toString();
		
		final byte[] bytes = Files.readAllBytes(Path.of(file));
		final String json = new String(bytes, "UTF8");
		
		final JsonElement tokens = JsonParser.parseString(json);
		final JsonArray root = tokens.getAsJsonArray();
		
		signatures = new HashMap<>();
		
		for (var item : root) {
			final JsonObject itemObj = item.getAsJsonObject();
			final PsyqSig sig = PsyqSig.fromJsonToken(itemObj);
			
			signatures.put(sig.getName(), sig);
		}
	}
	
	public Map<String, PsyqSig> getSignatures() {
		return signatures;
	}
	
	public void applySignatures(Program program, Address startAddr, Address endAddr, TaskMonitor monitor, MessageLog log) {
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		
		int appliedObjs = 0;
		int totalObjs = signatures.size();
		boolean showCount = false;
		
		monitor.initialize(totalObjs);
		monitor.setMessage("Applying obj symbols...");
		monitor.clearCanceled();
		
		for (var item : signatures.entrySet()) {
			if (monitor.isCancelled()) {
				break;
			}
			
			final PsyqSig sig = item.getValue();
			
			if (sig.isApplied()) {
				continue;
			}
			
			final MaskedBytes bytes = sig.getSig();
			final Map<String, Long> labels = sig.getLabels();
			
			Address searchAddr = startAddr;
			boolean applied = false;
			
			while (!monitor.isCancelled() && searchAddr.compareTo(endAddr) == -1 && !applied) {
				final Address addr = program.getMemory().findBytes(searchAddr, endAddr, bytes.getBytes(), bytes.getMasks(), true, monitor);
				
				if (addr == null) {
					monitor.incrementProgress(1);
					break;
				}
				
				for (var lb : labels.entrySet()) {
					final String lbName = lb.getKey();
					final long lbOffset = lb.getValue();
					
					final Address lbAddr = addr.add(lbOffset);
					final MemoryBlock block = memory.getBlock(lbAddr);
					
					if (block == null) {
						continue;
					}
					
					if (block.isExecute() && block.isInitialized()) {
						showCount = true;
						
						if (listing.getInstructionAt(lbAddr) == null) {
							DisassembleCommand disCmd = new DisassembleCommand(new AddressSet(lbAddr), null);
							disCmd.applyTo(program);
						}
						
						boolean isFunction = !lbName.startsWith("loc_");
						final String newLbName = lbName.replace("text_", String.format("%s_", sig.getName().replace(".", "_")));
						setFunction(program, fpa, lbAddr, newLbName, isFunction, false, log);
						
						monitor.setMessage(String.format("Symbol %s at 0x%08X", newLbName, lbAddr.getOffset()));
						
						if (isFunction) {
							applied = true;
						}
					}
				}
				
				searchAddr = addr.add(4);
				monitor.incrementProgress(1);
			}
			
			sig.setApplied(applied);
			
			if (applied) {
				appliedObjs += 1;
			}
		}
		
		if (showCount) {
			log.appendMsg(String.format("Applied in %s: %d/%d", file, appliedObjs, totalObjs));
		}
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
			
			if (isFunction && program.getSymbolTable().hasSymbol(address)) {
				return;
			}
			
			program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
}

package pat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class PatParser {
	private static final Pattern modulePat = Pattern.compile("([:\\^][0-9A-F]{4}@?) ([\\.\\w]+) ");
	private static final Pattern linePat = Pattern.compile("^((?:[0-9A-F\\.]{2})+) ([0-9A-F]{2}) ([0-9A-F]{4}) ([0-9A-F]{4}) ((?:[:\\^][0-9A-F]{4}@? [\\.\\w]+ )+)((?:[0-9A-F\\.]{2})+)?$");

	private List<SignatureData> signatures = null;
	private final TaskMonitor monitor;
	private boolean skipRefs = true;
	private long modulesCount = 0L;

	public PatParser(File file, TaskMonitor monitor) throws IOException {
		BufferedReader reader;
		List<String> lines = new ArrayList<String>();
		
		reader = new BufferedReader(new FileReader(file));
		String line = reader.readLine();
		while (line != null) {
			lines.add(line);
			line = reader.readLine();
		}
		reader.close();
		
		this.monitor = monitor;
		parse(lines);
	}
	
	public PatParser(List<SignatureData> signatures, TaskMonitor monitor) {
		this.monitor = monitor;
		this.signatures = signatures;
		getAllModulesCount();
	}
	
	public void setSkipRefs(boolean skip) {
		skipRefs = skip;
	}
	
	public void applySignatures(ByteProvider provider, Program program, Address imageBase, Address startAddr, Address endAddr, MessageLog log) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);
		PseudoDisassembler ps = new PseudoDisassembler(program);
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		
		monitor.initialize(getAllModulesCount());
		monitor.setMessage("Applying signatures...");
		
		for (SignatureData sig : signatures) {
			MaskedBytes fullBytes = sig.getFullBytes();
			MaskedBytes tmpl = sig.getTemplateBytes();
			
			Address addr = program.getMemory().findBytes(startAddr, endAddr, fullBytes.getBytes(), fullBytes.getMasks(), true, TaskMonitor.DUMMY);
			
			if (addr == null) {
				monitor.incrementProgress(sig.getModules().size());
				continue;
			}
			
			addr = addr.subtract(imageBase.getOffset());
			
			byte[] nextBytes = reader.readByteArray(addr.getOffset() + tmpl.getLength(), sig.getCrc16Length());
			
			if (!PatParser.checkCrc16(nextBytes, sig.getCrc16())) {
				monitor.incrementProgress(sig.getModules().size());
				continue;
			}
			
			addr = addr.add(imageBase.getOffset());
			
			List<ModuleData> modules = sig.getModules();
			for (ModuleData data : modules) {
				Address _addr = addr.add(data.getOffset());
				
				if (data.getType().isGlobal()) {
					setFunction(program, fpa, _addr, data.getName(), data.getType().isGlobal(), false, log);
				}
				else if (!skipRefs && data.getType().isReference()) {
					setInstrRefName(program, fpa, ps, _addr, data.getName(), log);
				}
				
				if (!(skipRefs && data.getType().isReference())) {
					monitor.setMessage(String.format("%s function %s at 0x%08X", data.getType(), data.getName(), _addr.getOffset()));
				}
				
				monitor.incrementProgress(1);
			}
		}
	}
	
	private void parse(List<String> lines) {
		modulesCount = 0L;
		
		signatures = new ArrayList<SignatureData>();
		
		int linesCount = lines.size();
		
		monitor.initialize(linesCount);
		monitor.setMessage("Reading signatures...");
		
		for (int i = 0; i < linesCount; ++i) {
			String line = lines.get(i);
			Matcher m = linePat.matcher(line);
			
			if (m.matches()) {
				MaskedBytes pp = hexStringToMaskedBytesArray(m.group(1));
				int ll = Integer.parseInt(m.group(2), 16);
				short ssss = (short)Integer.parseInt(m.group(3), 16);
				int llll = Integer.parseInt(m.group(4), 16);
				
				List<ModuleData> modules = parseModuleData(m.group(5));
				
				MaskedBytes tail = null;
				if (m.group(6) != null) {
					tail = hexStringToMaskedBytesArray(m.group(6));
				}
				
				signatures.add(new SignatureData(pp, ll, ssss, llll, modules, tail));
				modulesCount += modules.size();
			}
			monitor.incrementProgress(1);
		}
	}
	
	private List<ModuleData> parseModuleData(String s) {
		List<ModuleData> res = new ArrayList<ModuleData>();
		
		if (s != null) {
			Matcher m = modulePat.matcher(s);
			
			while (m.find()) {
				String __offset = m.group(1);
				
				ModuleType type = __offset.startsWith(":") ? ModuleType.GLOBAL_NAME : ModuleType.REF_NAME;
				type = (type == ModuleType.GLOBAL_NAME && __offset.endsWith("@")) ? ModuleType.LOCAL_NAME : type;
				
				String _offset = __offset.replaceAll("[:^@]", "");
				
				long offset = Integer.parseInt(_offset, 16);
				String name = m.group(2);
				
				res.add(new ModuleData(offset, name, type));
			}
		}
		
		return res;
	}
	
	public long getAllModulesCount() {
		if (modulesCount == 0L) {
			for (SignatureData data : signatures) {
				modulesCount += data.getModules().size();
			}
		}
		
		return modulesCount;
	}
	
	public static void setInstrRefName(Program program, FlatProgramAPI fpa, PseudoDisassembler ps, Address address, String name, MessageLog log) {
		ReferenceManager refsMgr = program.getReferenceManager();
		
		Reference[] refs = refsMgr.getReferencesFrom(address);
		
		if (refs.length == 0) {
			disasmInstruction(program, address);
			refs = refsMgr.getReferencesFrom(address);
			
			if (refs.length == 0) {
				refs = refsMgr.getReferencesFrom(address.add(4));
				
				if (refs.length == 0) {
					refs = refsMgr.getFlowReferencesFrom(address.add(4));
					
					Instruction instr = program.getListing().getInstructionAt(address.add(4));
					
					if (instr == null) {
						disasmInstruction(program, address.add(4));
						instr = program.getListing().getInstructionAt(address.add(4));
						
						if (instr == null) {
							return;
						}
					}
					
					FlowType flowType = instr.getFlowType();
					
					if (refs.length == 0 && !(flowType.isJump() || flowType.isCall() || flowType.isTerminal())) {
						return;
					}
					
					refs = refsMgr.getReferencesFrom(address.add(8));
					
					if (refs.length == 0) {
						return;
					}
				}
			}
		}
		
		try {
			program.getSymbolTable().createLabel(refs[0].getToAddress(), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
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
	
	private MaskedBytes hexStringToMaskedBytesArray(String s) {
		MaskedBytes res = null;
		
		if (s != null) {
		    int len = s.length();
		    byte[] bytes = new byte[len / 2];
		    byte[] masks = new byte[len / 2];
		    for (int i = 0; i < len; i += 2) {
		    	char c1 = s.charAt(i);
		    	char c2 = s.charAt(i + 1);
		    	
		    	masks[i / 2] = (byte) (
		    			(((c1 == '.') ? 0x0 : 0xF) << 4) |
		    			(((c2 == '.') ? 0x0 : 0xF) << 0)
		    			);
		    	bytes[i / 2] = (byte) (
		    			(((c1 == '.') ? 0x0 : Character.digit(c1, 16)) << 4) |
		    			(((c2 == '.') ? 0x0 : Character.digit(c2, 16)) << 0)
		    			);
		    	
		    }
		    
		    res = new MaskedBytes(bytes, masks);
		}
	    
	    return res;
	}
	
	public static boolean checkCrc16(byte[] bytes, short resCrc) {
		if ( bytes.length == 0 )
			return true;

		int crc = 0xFFFF;

		for (int i = 0; i < bytes.length; ++i) {
	        int a = bytes[i];
	        
	        for (int x = 0; x < 8; ++x) {
	        	if (((crc ^ a) & 1) != 0) {
	        		crc = (crc >> 1) ^ 0x8408;
	        	}
	        	else {
	        		crc >>= 1;
	        	}
	        	
	        	a >>= 1;
	        }
		}
		
		crc = ~crc;
        int x = crc;
        crc = (crc << 8) | ((x >> 8) & 0xFF);
        
        crc &= 0xFFFF;

	    return (short)crc == resCrc;
	}
	
	public List<SignatureData> getSignatures() {
		return signatures;
	}
}

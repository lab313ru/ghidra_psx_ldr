package pat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class PatParser {
	private static final Pattern modulePat = Pattern.compile("([:\\^][0-9A-F]{4}@?) ([\\.\\w]+) ");
	private static final Pattern linePat = Pattern.compile("^((?:[0-9A-F\\.]{2})+) ([0-9A-F]{2}) ([0-9A-F]{4}) ([0-9A-F]{4}) ((?:[:\\^][0-9A-F]{4}@? [\\.\\w]+ )+)((?:[0-9A-F\\.]{2})+)?$");

	private List<SignatureData> signatures = null;
	private TaskMonitor monitor;
	
	private HashSet<AddressSetView> analyzed;

	public PatParser(File file, TaskMonitor monitor) throws IOException {
		BufferedReader reader;
		List<String> lines = new ArrayList<>();
		
		reader = new BufferedReader(new FileReader(file));
		String line = reader.readLine();
		while (line != null) {
			lines.add(line);
			line = reader.readLine();
		}
		reader.close();
		
		this.monitor = monitor;
		analyzed = new HashSet<>();

		parse(lines);
	}
	
	private boolean alreadyAnalyzed(Address startAddr, Address endAddr) {
		for (AddressSetView set : analyzed) {
			if (set.contains(startAddr, endAddr)) {
				return true;
			}
		}
		
		return false;
	}
	
	public void applySignatures(Program program, Address startAddr, Address endAddr, MessageLog log) {
		if (alreadyAnalyzed(startAddr, endAddr)) {
			return;
		}
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();
		Memory memory = program.getMemory();
		
		monitor.initialize(getModulesCount(true));
		monitor.setMessage("Applying global symbols...");
		
		for (SignatureData sig : signatures) {
			if (monitor.isCancelled()) {
				break;
			}
			
			MaskedBytes fullBytes = sig.getFullBytes();
			MaskedBytes tmpl = sig.getTemplateBytes();
			
			ModuleData[] gModules = sig.getModules(true);
			
			Address searchAddr = startAddr;
			while (!monitor.isCancelled() && searchAddr.compareTo(endAddr) == -1) {
				Address addr = program.getMemory().findBytes(searchAddr, endAddr, fullBytes.getBytes(), fullBytes.getMasks(), true, TaskMonitor.DUMMY);
				
				if (addr == null) {
					monitor.incrementProgress(gModules.length);
					break;
				}
	
				if (checkCrc(memory, sig, addr, tmpl.getLength(), gModules.length)) {
					searchAddr = addr.add(4);
					continue;
				}
	
				for (ModuleData data : gModules) {
					if (monitor.isCancelled()) {
						break;
					}
					
					Address _addr = addr.add(data.getOffset());
					
					MemoryBlock block = memory.getBlock(_addr);
					
					if (block == null) {
						monitor.incrementProgress(1);
						continue;
					}
					
					if (block.isExecute() && block.isInitialized()) {
						if (listing.getInstructionAt(_addr) == null) {
							DisassembleCommand disCmd = new DisassembleCommand(new AddressSet(_addr), null);
							disCmd.applyTo(program);
						}
						
						setFunction(program, fpa, _addr, data.getName(), data.getType().isGlobal(), false, log);
					}
					
					if (nameLabel(symbolTable, _addr, data.getName(), log)) {
						monitor.incrementProgress(1);
						continue;
					}
					
					monitor.setMessage(String.format("%s symbol %s at 0x%08X", data.getType(), data.getName(), _addr.getOffset()));
					
					monitor.incrementProgress(1);
				}
				
				break;
			}
		}
		
		monitor.initialize(getModulesCount(false));
		monitor.setMessage("Applying referenced symbols...");
		
		for (SignatureData sig : signatures) {
			if (monitor.isCancelled()) {
				break;
			}
			
			MaskedBytes fullBytes = sig.getFullBytes();
			MaskedBytes tmpl = sig.getTemplateBytes();
			
			ModuleData[] lModules = sig.getModules(false);
			
			Address searchAddr = startAddr;
			while (!monitor.isCancelled() && searchAddr.compareTo(endAddr) == -1) {
				Address addr = program.getMemory().findBytes(searchAddr, endAddr, fullBytes.getBytes(), fullBytes.getMasks(), true, TaskMonitor.DUMMY);

				if (addr == null) {
					monitor.incrementProgress(lModules.length);
					break;
				}
				
				if (checkCrc(memory, sig, addr, tmpl.getLength(), lModules.length)) {
					searchAddr = addr.add(4);
					continue;
				}
				
				for (ModuleData data : lModules) {
					if (monitor.isCancelled()) {
						break;
					}
					
					Address _addr = addr.add(data.getOffset());
					
					Symbol sym = symbolTable.getNamespaceSymbol(data.getName(), program.getGlobalNamespace());
					
					if (sym == null) {
						Instruction instr = listing.getInstructionAt(_addr);
						
						if (instr == null) {
							DisassembleCommand disasm = new DisassembleCommand(new AddressSet(_addr), null);
							disasm.applyTo(program);
							
							instr = listing.getInstructionAt(_addr);
							
							if (instr == null) {
								monitor.incrementProgress(1);
								continue;
							}
						}
						
						Reference[] refs = instr.getReferencesFrom();
						
						if (refs.length == 0) {
							monitor.incrementProgress(1);
							continue;
						}
						
						Address symRef = refs[0].getToAddress();
						
						if (!memory.contains(symRef)) {
							monitor.incrementProgress(1);
							continue;
						}
						
						if (!symbolTable.hasSymbol(symRef)) {
							if (nameLabel(symbolTable, symRef, data.getName(), log)) {
								monitor.incrementProgress(1);
								continue;
							}
						} else {
							sym = symbolTable.getSymbol(refs[0]);
						}
						
						if (sym == null) {
							monitor.incrementProgress(1);
							continue;
						}
					}
					
					Address toAddr = sym.getAddress();
					
					SymbolType symType = sym.getSymbolType();
					if (!symType.equals(SymbolType.GLOBAL_VAR) &&
						!symType.equals(SymbolType.CODE) &&
						!symType.equals(SymbolType.FUNCTION)) {
						monitor.incrementProgress(1);
						continue;
					}
					
					if (nameLabel(symbolTable, toAddr, data.getName(), log)) {
						monitor.incrementProgress(1);
						continue;
					}
					
					monitor.setMessage(String.format("%s symbol %s at 0x%08X", data.getType(), data.getName(), _addr.getOffset()));
					
					monitor.incrementProgress(1);
				}
				
				break;
			}
		}
		
		analyzed.add(new AddressSet(startAddr, endAddr));
	}
	
	private boolean nameLabel(SymbolTable tbl, Address addr, String name, MessageLog log) {
		try {
			tbl.createLabel(addr, name, SourceType.USER_DEFINED);
		} catch (InvalidInputException e) {
			log.appendException(e);
			return true;
		}
		
		return false;
	}
	
	private boolean checkCrc(Memory mem, SignatureData sig, Address addr, int tmplLength, int modulesLength) {
		if (sig.getCrc16Length() != 0) {
			byte[] crcBytes = new byte[sig.getCrc16Length()];
			try {
				int crcBytesRead = mem.getBytes(addr.add(tmplLength), crcBytes);
				
				if (crcBytesRead != crcBytes.length) {
					monitor.incrementProgress(modulesLength);
					return true;
				}
			} catch (MemoryAccessException | AddressOutOfBoundsException e1) {
				monitor.incrementProgress(modulesLength);
				return true;
			}

			return !PatParser.checkCrc16(crcBytes, sig.getCrc16());
		}
		
		return false;
	}
	
	private void parse(List<String> lines) {
		signatures = new ArrayList<>();
		
		int linesCount = lines.size();
		
		monitor.initialize(linesCount);
		monitor.setMessage("Reading signatures...");

		for (String line : lines) {
			Matcher m = linePat.matcher(line);

			if (m.matches()) {
				MaskedBytes pp = hexStringToMaskedBytesArray(m.group(1));
				int ll = Integer.parseInt(m.group(2), 16);
				short ssss = (short) Integer.parseInt(m.group(3), 16);
				int llll = Integer.parseInt(m.group(4), 16);

				List<ModuleData> modules = parseModuleData(m.group(5));

				MaskedBytes tail = null;
				if (m.group(6) != null) {
					tail = hexStringToMaskedBytesArray(m.group(6));
				}

				signatures.add(new SignatureData(pp, ll, ssss, llll, modules, tail));
			}
			monitor.incrementProgress(1);
		}
	}
	
	private List<ModuleData> parseModuleData(String s) {
		List<ModuleData> res = new ArrayList<>();
		
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
	
	private long getModulesCount(boolean global) {
		long modulesCount = 0L;
		
		for (SignatureData data : signatures) {
			modulesCount += data.getModules(global).length;
		}
		
		return modulesCount;
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
		    			(((c2 == '.') ? 0x0 : 0xF))
		    			);
		    	bytes[i / 2] = (byte) (
		    			(((c1 == '.') ? 0x0 : Character.digit(c1, 16)) << 4) |
		    			(((c2 == '.') ? 0x0 : Character.digit(c2, 16)))
		    			);
		    	
		    }
		    
		    res = new MaskedBytes(bytes, masks);
		}
	    
	    return res;
	}
	
	private static boolean checkCrc16(byte[] bytes, short resCrc) {
		if ( bytes.length == 0 )
			return true;

		int crc = 0xFFFF;

		for (int aByte : bytes) {
			int a = aByte;

			for (int x = 0; x < 8; ++x) {
				if (((crc ^ a) & 1) != 0) {
					crc = (crc >> 1) ^ 0x8408;
				} else {
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

}

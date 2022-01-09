package psx;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import generic.test.TestUtils;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionShellSymbol;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class PsxUpdateAddressSpacesTask extends Task {

	public static final String OVERRIDES = "decompilerOverrides";
	
	private DecompilerProvider decompProvider;
	private DecompilerController decompController;
	private final Map<Address, String> entries;
	private ClangToken selected;
	private List<PsxUpdateAddressSpacesOverride> map;
	private PsxPlugin psxPlugin;
	
	public PsxUpdateAddressSpacesTask(PsxPlugin psxPlugin, DecompilerProvider decompProvider, List<PsxUpdateAddressSpacesOverride> map, final Map<Address, String> entries, ClangToken selected) {
		super("Update Overlayed AddressSpace References", true, false, true, true);
		this.decompProvider = decompProvider;
		this.decompController = (DecompilerController)TestUtils.getInstanceField("controller", decompProvider);
		this.entries = entries;
		this.map = map;
		this.selected = selected;
		this.psxPlugin = psxPlugin;
	}
	
	@Override
	public void run(TaskMonitor monitor) {
		DecompilerPanel panel = decompController.getDecompilerPanel();
		HighFunction func = decompController.getHighFunction();
		Program program = decompController.getProgram();
		AddressFactory addrFactory = program.getAddressFactory();
		AddressSpace defSpace = addrFactory.getDefaultAddressSpace();
		AddressSpace constSpace = addrFactory.getConstantSpace();
		
		if (func == null) {
			return;
		}
		
		final Address funcAddr = func.getFunction().getEntryPoint();
		
		for (final Map.Entry<Address, String> entry : entries.entrySet()) {
			final Address symAddr = entry.getKey();
			final String name = entry.getValue();
			
			List<ClangToken> tokens = panel.findTokensByName(name);
			
			if (tokens.size() == 0) {
				String symName = findAnotherSpaceSymbolName(defSpace, symAddr.getOffset());
				
				if (symName == null) {
					continue;
				}
				
				tokens = panel.findTokensByName(symName);
			}
			
			if (tokens.size() == 0) { // WARNING!: hack to find undefined function naming "func_0xXXXXXXXX"
				tokens = panel.findTokensByName(String.format("func_0x%08x", symAddr.getOffset()));
			}
			
			if (tokens.size() == 0) { // here can be a constant resolved string, it's OK
				continue;
			}
			
			if (tokens.size() == 1) {
				ClangToken token = tokens.get(0);
				
				if (!isValidToken(token)) {
					continue;
				}
				
				workWithToken(constSpace, token, funcAddr, symAddr, false);
			} else if (selected != null) {
				if (!isValidToken(selected)) {
					continue;
				}
				
				for (ClangToken token : tokens) {
					if (!selected.equals(token)) {
						continue;
					}

					workWithToken(constSpace, token, funcAddr, symAddr, true);
				}
			} else {
				// here we have multiple references to the same address from the decompiler.
				// It can be single or multiple overlays references,
				// so the user should use my special decompiler action to upgrade selected tokens
				
				Iterator<PsxUpdateAddressSpacesOverride> overrides = psxPlugin.getOverrides().getOverridesIterator();
				
				while (overrides.hasNext()) {
					PsxUpdateAddressSpacesOverride override = overrides.next();
					
					for (ClangToken token : tokens) {
						if (!override.getFunctionAddress().equals(funcAddr.toString())) {
							continue;
						}
						
						if (override.getLineNumber() != token.getLineParent().getLineNumber()) {
							continue;
						}
						
						if (!symAddr.equals(addrFactory.getAddress(override.getSymbolAddress()))) {
							continue;
						}
						
						workWithToken(constSpace, token, funcAddr, symAddr, false);
					}
				}
			}
		}
		
		decompController.setDecompileData(decompController.getDecompileData());
	}
	
	private static boolean isValidToken(final ClangToken token) {
		return (token instanceof ClangVariableToken) || (token instanceof ClangFuncNameToken);
	}
	
	private String findAnotherSpaceSymbolName(final AddressSpace space, long offset) {
		SymbolTable symTable = decompProvider.getProgram().getSymbolTable();
		
		Symbol sym = symTable.getPrimarySymbol(space.getAddress(offset));
		
		return (sym != null) ? sym.getName() : null;
	}
	
	private void workWithToken(AddressSpace constSpace, ClangToken token, final Address funcAddr, final Address newAddr, boolean store) {		
		PcodeOp op = token.getPcodeOp();
		
		int spaceId = newAddr.getAddressSpace().getSpaceID();
		int lineNum = token.getLineParent().getLineNumber();
		
		for (int i = 0; i < op.getNumInputs(); ++i) {
			VarnodeAST in = (VarnodeAST) op.getInput(i);
			
			applyVarnodeOverlay(token, in, newAddr, spaceId);
		}
		
		if (store) {
			PsxUpdateAddressSpacesOverride override = new PsxUpdateAddressSpacesOverride(funcAddr.toString(), lineNum, newAddr.toString());
			map.add(override);
		}
		
		Varnode out = op.getOutput();
		
		if (out != null) {
			applyVarnodeOverlay(token, (VarnodeAST) out, newAddr, spaceId);
		}
	}
	
	private void applyVarnodeOverlay(ClangToken token, VarnodeAST varnode, final Address newAddr, int spaceId) {
		if (varnode == null) {
			return;
		}
		
		if (varnode.getAddress().getOffset() != newAddr.getOffset()) {
			return;
		}
		
		TestUtils.setInstanceField("address", varnode, newAddr);
		TestUtils.setInstanceField("spaceID", varnode, spaceId);
		
		Symbol newSymbol = getReferencedSymbol(decompProvider.getProgram(), newAddr);
		
		if (newSymbol == null) {
			return;
		}
		
		if (token instanceof ClangVariableToken) {
			HighVariable highVar = varnode.getHigh();
			HighSymbol symbol = highVar.getSymbol();
			VariableStorage storage = symbol.getStorage();
			Varnode symbolVarnode = storage.getFirstVarnode();

			TestUtils.setInstanceField("address", symbolVarnode, newAddr);
			TestUtils.setInstanceField("spaceID", symbolVarnode, spaceId);
			
			if (!(symbol instanceof HighFunctionShellSymbol)) { // like some function has been passed as an argument to another function
				TestUtils.setInstanceField("symbol", symbol, newSymbol);
			}
			
			TestUtils.setInstanceField("id", symbol, newSymbol.getID());
			TestUtils.setInstanceField("name", symbol, newSymbol.getName());
		}
		
		TestUtils.setInstanceField("text", token, newSymbol.getName());
	}
	
	private static Symbol getReferencedSymbol(Program program, Address addr) {
		SymbolTable symTable = program.getSymbolTable();

		Symbol[] symbols = symTable.getSymbols(addr);
		
		for (Symbol symbol : symbols) {
			if (symbol.isPrimary()) {
				return symbol;
			}
		}
		
		return null;
	}
}

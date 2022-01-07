package psx;

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
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class PsxUpdateAddressSpacesTask extends Task {

	private DecompilerProvider decompProvider;
	private DecompilerController decompController;
	private final Map<String, Address> entries;
	
	public PsxUpdateAddressSpacesTask(DecompilerProvider decompProvider, final Map<String, Address> entries) {
		super("Update Overlayed AddressSpace References", true, false, true, true);
		this.decompProvider = decompProvider;
		this.decompController = (DecompilerController)TestUtils.getInstanceField("controller", decompProvider);
		this.entries = entries;
	}
	
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		DecompilerPanel panel = decompController.getDecompilerPanel();
		HighFunction func = decompController.getHighFunction();
		
		if (func == null) {
			return;
		}
		
		for (Map.Entry<String, Address> entry : entries.entrySet()) {
			List<ClangToken> tokens = panel.findTokensByName(entry.getKey());
			
			if (tokens.size() == 0) {
				String symName = findAnotherSpaceSymbolName(decompProvider.getProgram(), entry.getValue());
				
				if (symName == null) {
					continue;
				}
				
				tokens = panel.findTokensByName(symName);
			}
			
			for (ClangToken token : tokens) {
				if (!(token instanceof ClangVariableToken) && !(token instanceof ClangFuncNameToken)) {
					continue;
				}
				
				workWithToken(token, entry.getValue());
			}
		}
	}
	
	private static String findAnotherSpaceSymbolName(Program program, final Address address) {
		Symbol sym = program.getSymbolTable().getPrimarySymbol(address);
		
		if (sym == null) {
			return null;
		}
		
		return sym.getName();
	}
	
	private void workWithToken(ClangToken token, final Address newAddr) {
		PcodeOp op = token.getPcodeOp();
		
		VarnodeAST in;
		
		if (token instanceof ClangVariableToken) {
			in = (VarnodeAST) op.getInput(1);
		} else {
			in = (VarnodeAST) op.getInput(0);
		}
		
		int spaceId = newAddr.getAddressSpace().getSpaceID();
		
		TestUtils.setInstanceField("address", in, newAddr);
		TestUtils.setInstanceField("spaceID", in, spaceId);
		
		Symbol newSymbol = getReferencedSymbol(decompProvider.getProgram(), newAddr);
		
		if (newSymbol == null) {
			return;
		}
		
		if (token instanceof ClangVariableToken) {
			HighVariable highVar = in.getHigh();
			HighSymbol symbol = highVar.getSymbol();
			VariableStorage storage = symbol.getStorage();
			Varnode symbolVarnode = storage.getFirstVarnode();

			TestUtils.setInstanceField("address", symbolVarnode, newAddr);
			TestUtils.setInstanceField("spaceID", symbolVarnode, spaceId);
			
			TestUtils.setInstanceField("symbol", symbol, newSymbol);
			TestUtils.setInstanceField("id", symbol, newSymbol.getID());
			TestUtils.setInstanceField("name", symbol, newSymbol.getName());
		}
		
		TestUtils.setInstanceField("text", token, newSymbol.getName());
		
		decompController.setDecompileData(decompController.getDecompileData());
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

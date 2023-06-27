package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangReturnType;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.TaskLauncher;
import psx.PsxAnalyzer;
import psx.PsxPlugin;
import psx.PsxUpdateAddressSpacesOverride;
import psx.PsxUpdateAddressSpacesTask;

public class PsxUpdateAddressSpacesAction extends AbstractDecompilerAction {
	
	private static final String NAME = "Update Symbol Address Space";
	
	public PsxUpdateAddressSpacesAction() {
		super(NAME);
		
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK));
		setPopupMenuData(new MenuData(new String[] { NAME }, "Decompiler"));
	}
	
	private boolean isFunctionCall(ClangToken tokenAtCursor) {
		return (tokenAtCursor instanceof ClangFuncNameToken);
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!PsxAnalyzer.isPsxLoaderOrPsxLanguage(context.getProgram())) {
			return false;
		}
		
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			return false;
		}
		if (tokenAtCursor.Parent() instanceof ClangReturnType) {
			return false;
		}

		HighSymbol highSymbol = tokenAtCursor.getHighSymbol(context.getHighFunction());
		if (highSymbol == null) {
			return isFunctionCall(tokenAtCursor);
		}
		return highSymbol.isGlobal();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		PluginTool tool = context.getTool();
		
		Function func = context.getFunction();
		
		DecompilerProvider decompProvider = context.getComponentProvider();
		
		PsxPlugin psxPlugin = PsxPlugin.getPsxPlugin(tool);
		
		List<PsxUpdateAddressSpacesOverride> newMap = new ArrayList<>();
		
		Map<Address, String> entries = PsxPlugin.collectFunctionOverlayedEntries(decompProvider, func);
		PsxUpdateAddressSpacesTask task = new PsxUpdateAddressSpacesTask(psxPlugin, decompProvider, newMap, entries, context.getTokenAtCursor());
		new TaskLauncher(task, tool.getToolFrame());
		
		psxPlugin.mergeOverrides(newMap);
	}

}

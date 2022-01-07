/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package psx;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import generic.test.TestUtils;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.app.decompiler.component.DecompilerCallbackHandler;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.task.TaskLauncher;
import psx.debug.DebuggerProvider;
import utility.function.Callback;
import ghidra.MiscellaneousPluginPackage;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "This plugin creates/imports overlayed binaries for PSX.",
	description = "This plugin gives an ability to create/import binaries into an overlayed blocks for PSX.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class PsxPlugin extends ProgramPlugin {

	private DebuggerProvider dbgProvider;
	private OverlayManagerProvider omProvider;
	private DecompilerController decompController;
	private DecompilerProvider decompProvider;
	private boolean updatingDecompiler;
	private DecompilerCallbackHandler callbackHandler;

	public PsxPlugin(PluginTool tool) {
		super(tool, true, false);
	}
	
	@Override
	public void programActivated(Program program) {
		if (PsxAnalyzer.isPsxLoader(program)) {
			createOmAction();
			createDbgAction();
			
			DecompilePlugin decompiler = getDecompilerPlugin(tool);
			
			decompProvider = (DecompilerProvider)TestUtils.getInstanceField("connectedProvider", decompiler);
			
			decompController = (DecompilerController)TestUtils.getInstanceField("controller", decompProvider);
			callbackHandler = (DecompilerCallbackHandler)TestUtils.getInstanceField("callbackHandler", decompController);
			
			updatingDecompiler = false;
			
			TestUtils.setInstanceField("callbackHandler", decompController, new DecompilerCallbackHandler() {

				@Override
				public void decompileDataChanged(DecompileData decompileData) {
					if (updatingDecompiler) {
						return;
					}
					
					updatingDecompiler = true;
					
					if (decompileData != null) {
						DecompileResults results = decompileData.getDecompileResults();
						
						if (results != null) {
							if (results.decompileCompleted()) {
								HighFunction highFunc = decompileData.getHighFunction();
								if (highFunc != null) {
									decompileFunc(highFunc.getFunction());
								}
							}
						}
					}
					
					updatingDecompiler = false;
				
					callbackHandler.decompileDataChanged(decompileData);
				}

				@Override
				public void contextChanged() {
					callbackHandler.contextChanged();
				}

				@Override
				public void setStatusMessage(String message) {
					callbackHandler.setStatusMessage(message);
				}

				@Override
				public void locationChanged(ProgramLocation programLocation) {
					callbackHandler.locationChanged(programLocation);
				}

				@Override
				public void selectionChanged(ProgramSelection programSelection) {
					callbackHandler.selectionChanged(programSelection);
				}

				@Override
				public void annotationClicked(AnnotatedTextFieldElement annotation, boolean newWindow) {
					callbackHandler.annotationClicked(annotation, newWindow);
				}

				@Override
				public void goToLabel(String labelName, boolean newWindow) {
					callbackHandler.goToLabel(labelName, newWindow);
				}

				@Override
				public void goToAddress(Address addr, boolean newWindow) {
					callbackHandler.goToAddress(addr, newWindow);
				}

				@Override
				public void goToScalar(long value, boolean newWindow) {
					callbackHandler.goToScalar(value, newWindow);
				}

				@Override
				public void exportLocation() {
					callbackHandler.exportLocation();
				}

				@Override
				public void goToFunction(Function function, boolean newWindow) {
					callbackHandler.goToFunction(function, newWindow);
				}

				@Override
				public void doWheNotBusy(Callback c) {
					callbackHandler.doWheNotBusy(c);
				}
				
			});
			
			// PsxLoader.loadPsyqGdt(program);
			gotoMain(this.getTool(), program);
		}
	}
	
	@Override
	protected void programDeactivated(Program program) {
		TestUtils.setInstanceField("callbackHandler", decompController, callbackHandler);
	}
	
	private void decompileFunc(Function func) {
		Program program = decompProvider.getProgram();
		Listing listing = program.getListing();
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		AddressSetView set = func.getBody();
		
		AddressIterator addrIter = set.getAddresses(true);
		
		Map<String, Address> entries = new HashMap<>();
		
		while (addrIter.hasNext()) {
			Address addr = addrIter.next();
			
			Instruction instr = listing.getInstructionAt(addr);
			
			if (instr == null) {
				continue;
			}
			
			Reference[] instrRefs = instr.getReferencesFrom();
			
			for (Reference ref : instrRefs) {
				if (!isDifferentFromToAddressSpace(ref)) {
					continue;
				}
				
				Address symAddr = defaultSpace.getAddress(ref.getToAddress().getOffset());
				Symbol sym = program.getSymbolTable().getPrimarySymbol(symAddr);
				
				if (sym == null) {
					continue;
				}

				entries.put(sym.getName(), ref.getToAddress());
			}
		}
		
		PsxUpdateAddressSpacesTask task = new PsxUpdateAddressSpacesTask(decompProvider, entries);
		new TaskLauncher(task, tool.getToolFrame());
	}
	
	private boolean isDifferentFromToAddressSpace(final Reference ref) {
		return !ref.getFromAddress().getAddressSpace().equals(ref.getToAddress().getAddressSpace());
	}
	
	private static DecompilePlugin getDecompilerPlugin(PluginTool tool) {
		return (DecompilePlugin) tool.getManagedPlugins().stream().filter(p -> p.getClass() == DecompilePlugin.class).findFirst().get();
	}
	
	@Override
	protected void dispose() {
		if (dbgProvider == null) {
			return;
		}
		
		dbgProvider.close();
	}
	
	private static void gotoMain(PluginTool tool, Program program) {
		SymbolTable st = program.getSymbolTable();
		List<Symbol> mainSym = st.getGlobalSymbols("main");
		
		if (mainSym.size() > 0) {
			gotoPc(tool, program, "default", mainSym.get(0).getAddress().getOffset());
		}
	}
	
	public static void gotoPc(PluginTool tool, Program program, String addrSpace, long pcAddr) {
		GoToService gotoService = tool.getService(GoToService.class);
		
		AddressFactory af = program.getAddressFactory();
		AddressSpace as = af.getAddressSpace(addrSpace);
		
		if (as == null) {
			as = af.getDefaultAddressSpace();
		}
		
		if (gotoService != null) {
			Address addr = as.getAddress(pcAddr);
			gotoService.goTo(addr);
		}
	}
	
	private void createOmAction() {
		DockingAction openOverlayManagerAction = new DockingAction("PsxOverlayManager", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				if (omProvider != null) {
					omProvider.close();
				}
				
				omProvider = new OverlayManagerProvider(currentProgram);
				omProvider.showDialog(getTool());
			}
		};
		
		openOverlayManagerAction.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_TOOLS, "PSX Overlay Manager..."}, "Psx"));
		tool.addAction(openOverlayManagerAction);
	}
	
	private void createDbgAction() {
		DockingAction createDebuggerAction = new DockingAction("PsxDebugger", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				if (dbgProvider == null) {
					dbgProvider = new DebuggerProvider(getTool(), getName(), currentProgram);
				}
				
				if (!dbgProvider.isVisible()) {
					dbgProvider.setVisible(true);
				}
				
				dbgProvider.toFront();
			}
		};
		
		createDebuggerAction.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_TOOLS, "PSX Debugger..."}, "Psx"));
		tool.addAction(createDebuggerAction);
	}
	
	private static class OverlayManagerProvider extends DialogComponentProvider {

		public OverlayManagerProvider(Program program) {
			super("New Overlay from Data", true, true, true, false);
			
			addWorkPanel(new OverlayManager(program, this));
		}
		
		public void showDialog(PluginTool tool) {
			tool.showDialog(this);
		}
		
	}
}

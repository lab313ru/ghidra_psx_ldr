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

import java.util.ArrayList;
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
import ghidra.app.plugin.core.decompile.actions.PsxUpdateAddressSpacesAction;
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
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.task.TaskLauncher;
import utility.function.Callback;
import ghidra.MiscellaneousPluginPackage;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.DECOMPILER,
	shortDescription = "This plugin creates/imports overlayed binaries for PSX.",
	description = "This plugin gives an ability to create/import binaries into an overlayed blocks for PSX.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class PsxPlugin extends ProgramPlugin {

	private OverlayManagerProvider omProvider;
	private DecompilerController decompController;
	private DecompilerProvider decompProvider;
	private boolean updatingDecompiler;
	private DecompilerCallbackHandler callbackHandler;
	
	private PsxUpdateAddressSpacesOverrides oldMap;

	public PsxPlugin(PluginTool tool) {
		super(tool);
	}
	
	@Override
	public void programActivated(Program program) {
		if (PsxAnalyzer.isPsxLoaderOrPsxLanguage(program)) {
			createOmAction();

			oldMap = getOverrides(program);
			
			DecompilePlugin decompiler = getDecompilerPlugin(tool);
			
			decompProvider = (DecompilerProvider)TestUtils.getInstanceField("connectedProvider", decompiler);
			
			decompProvider.addLocalAction(new PsxUpdateAddressSpacesAction());
			
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
				public void doWhenNotBusy(Callback c) {
					callbackHandler.doWhenNotBusy(c);
				}
				
			});
			
			// PsxLoader.loadPsyqGdt(program);
			gotoMain(this.getTool(), program);
		}
	}
	
	@Override
	protected void programDeactivated(Program program) {
		if (decompController != null) {
			TestUtils.setInstanceField("callbackHandler", decompController, callbackHandler);
		}
		
		setOverrides(program, oldMap);
	}
	
	private PsxUpdateAddressSpacesOverrides getOverrides(Program program) {
		ProgramUserData data = program.getProgramUserData();
		
		int transactionId = data.startTransaction();
		ObjectPropertyMap<PsxUpdateAddressSpacesOverrides> map = data.getObjectProperty(PsxPlugin.class.getName(), PsxUpdateAddressSpacesTask.OVERRIDES, PsxUpdateAddressSpacesOverrides.class, true);
		Address objAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(PsxUpdateAddressSpacesOverrides.ADDRESS);

		data.endTransaction(transactionId);
		if (map.hasProperty(objAddress)) {
			return map.get(objAddress);
		}
		
		return new PsxUpdateAddressSpacesOverrides();
	}
	
	private void setOverrides(Program program, PsxUpdateAddressSpacesOverrides newOverrides) {
		if (newOverrides == null) {
			return;
		}
		
		ProgramUserData data = program.getProgramUserData();
		
		int transactionId = data.startTransaction();
		ObjectPropertyMap<PsxUpdateAddressSpacesOverrides> map = data.getObjectProperty(PsxPlugin.class.getName(), PsxUpdateAddressSpacesTask.OVERRIDES, PsxUpdateAddressSpacesOverrides.class, true);
		
		Address objAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(PsxUpdateAddressSpacesOverrides.ADDRESS);
		map.remove(objAddress);
		map.add(objAddress, newOverrides);
		
		data.endTransaction(transactionId);
	}
	
	public PsxUpdateAddressSpacesOverrides getOverrides() {
		return oldMap;
	}
	
	public void mergeOverrides(final List<PsxUpdateAddressSpacesOverride> newMap) {
		oldMap.mergeOverrides(newMap);
	}
	
	public static Map<Address, String> collectFunctionOverlayedEntries(DecompilerProvider decompProvider, final Function func) {
		Program program = decompProvider.getProgram();
		Listing listing = program.getListing();
		
		AddressSetView set = func.getBody();
		
		AddressIterator addrIter = set.getAddresses(true);
		
		Map<Address, String> entries = new HashMap<>();
		
		while (addrIter.hasNext()) {
			Address addr = addrIter.next();
			
			Instruction instr = listing.getInstructionAt(addr);
			
			if (instr == null) {
				continue;
			}
			
			final Reference[] instrRefs = instr.getReferencesFrom();
			
			for (final Reference ref : instrRefs) {
				final Address[] overRefs = getOverlayRefAddresses(ref);
				
				if (overRefs == null) {
					break;
				}
				
				for (final Address overRef : overRefs) {
					Symbol sym = program.getSymbolTable().getPrimarySymbol(overRef);
					
					if (sym != null) {
						entries.put(overRef, sym.getName());
					}
				}
			}
		}
		
		return entries;
	}
	
	private void decompileFunc(final Function func) {
		List<PsxUpdateAddressSpacesOverride> newMap = new ArrayList<>();
		Map<Address, String> entries = collectFunctionOverlayedEntries(decompProvider, func);
		PsxUpdateAddressSpacesTask task = new PsxUpdateAddressSpacesTask(this, decompProvider, newMap, entries, null);
		new TaskLauncher(task, tool.getToolFrame());
		
		oldMap.mergeOverrides(newMap);
	}

	private static Address[] getOverlayRefAddresses(final Reference ref) {
		if (!ref.isPrimary()) {
			return null;
		}
		
		AddressSpace fromSpace = ref.getFromAddress().getAddressSpace();
		AddressSpace toSpace = ref.getToAddress().getAddressSpace();
		
		List<Address> refs = new ArrayList<>();
		
		if (fromSpace.isOverlaySpace()) {
			refs.add(ref.getFromAddress());
		}
		
		if (toSpace.isOverlaySpace()) {
			refs.add(ref.getToAddress());
		}
		
		return refs.toArray(Address[]::new);
	}
	
	private static DecompilePlugin getDecompilerPlugin(PluginTool tool) {
		return (DecompilePlugin) tool.getManagedPlugins().stream().filter(p -> p.getClass() == DecompilePlugin.class).findFirst().get();
	}
	
	public static PsxPlugin getPsxPlugin(PluginTool tool) {
		return (PsxPlugin) tool.getManagedPlugins().stream().filter(p -> p.getClass() == PsxPlugin.class).findFirst().get();
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

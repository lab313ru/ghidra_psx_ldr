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

import java.util.List;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import psx.debug.DebuggerProvider;
import ghidra.MiscellaneousPluginPackage;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "This plugin creates/imports overlayed binaries for PSX.",
	description = "This plugin gives an ability to create/import binaries into an overlayed blocks for PSX.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class PsxPlugin extends ProgramPlugin {

	private DebuggerProvider dbgProvider;
	private OverlayManagerProvider omProvider;

	public PsxPlugin(PluginTool tool) {
		super(tool, true, false);
	}
	
	@Override
	public void programActivated(Program program) {
		super.programActivated(program);
		
		if (PsxAnalyzer.isPsxLoader(program)) {
			createOmAction();
			createDbgAction();
			
			loadPsyqGdt(program);
			gotoMain(this.getTool(), program);
		}
	}
	
	@Override
	protected void dispose() {
		if (dbgProvider == null) {
			return;
		}
		
		dbgProvider.close();
	}
	
	private static void loadPsyqGdt(Program program) {
		String gdtName = String.format("psyq%s", PsxLoader.getProgramPsyqVersion(program));
		PsxLoader.closePsyqDataTypeArchives(program, gdtName);
		PsxLoader.loadPsyqArchive(program, gdtName, null, TaskMonitor.DUMMY, new MessageLog());
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

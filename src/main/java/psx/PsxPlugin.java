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

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.MiscellaneousPluginPackage;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "This plugin creates/imports overlayed binaries for PSX.",
	description = "This plugin gives an ability to create/import binaries into an overlayed blocks for PSX."
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
			dbgProvider = new DebuggerProvider(tool, "PsxDebugger");
			createAction();
		}
	}
	
	private void createAction() {
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
		
		openOverlayManagerAction.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_TOOLS, "PSX Overlay Manager..."}, "PsxOverlayManager"));
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

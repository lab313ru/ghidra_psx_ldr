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

	private NewOverlayProvider provider;

	public PsxPlugin(PluginTool tool) {
		super(tool, false, false);
	}
	
	@Override
	public void programActivated(Program program) {
		super.programActivated(program);
		
		if (PsxAnalyzer.isPsxLoader(program)) {
			createAction();
		}
	}
	
	private void createAction() {
		DockingAction createOverlayFromBinAction = new DockingAction("PsxNewOverlay", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				if (provider == null) {
					provider = new NewOverlayProvider(currentProgram);
				}
				
				provider.showDialog(getTool());
			}
		};
		
		createOverlayFromBinAction.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_TOOLS, "PSX", "Overlay Manager..."}));
		tool.addAction(createOverlayFromBinAction);
	}
	
	private static class NewOverlayProvider extends DialogComponentProvider {

		public NewOverlayProvider(Program program) {
			super("New Overlay from Data", true, true, true, false);
			
			addWorkPanel(new OverlayManager(program, this));
		}
		
		public void showDialog(PluginTool tool) {
			tool.showDialog(this);
		}
		
	}
}

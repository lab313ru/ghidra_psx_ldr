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

import java.awt.BorderLayout;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.Msg;
import ghidra.MiscellaneousPluginPackage;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "This plugin imports overlayed binaries for PSX.",
	description = "This plugin gives an ability to import binaries into an overlayed blocks for PSX."
)
//@formatter:on
public class PsxPlugin extends ProgramPlugin {

	MyProvider provider;

	public PsxPlugin(PluginTool tool) {
		super(tool, false, false);
	}

	@Override
	public void init() {
		super.init();
	}
	
	@Override
	public void programOpened(Program program) {
		super.programOpened(program);
		
		provider = new MyProvider(this, program);
	}

	private static class MyProvider extends ComponentProvider {

		private Program program;
		private JPanel panel;
		private JFileChooser jfc;
		private DockingAction action;
		private JComboBox<String> blockChooser = new JComboBox<>();
		
		private Map<Integer, String> overlays = new HashMap<>();

		public MyProvider(Plugin plugin, Program program) {
			super(plugin.getTool(), plugin.getName(), plugin.getName());
			this.program = program;
			
			buildPanel();
			createActions();
		}

		private void buildPanel() {
			panel = new JPanel();
			panel.setLayout(new BorderLayout());
			
			jfc = new JFileChooser((String)null);
			jfc.setDialogTitle("Please, select overlay file...");
			jfc.setMultiSelectionEnabled(false);
			
			blockChooser.removeAllItems();
			overlays.clear();
			
			Memory mem = program.getMemory();
			MemoryBlock[] memBlocks = mem.getBlocks();
			for (int i = 0; i < memBlocks.length; ++i) {
				MemoryBlock block = memBlocks[i];
				if (block.getType() == MemoryBlockType.OVERLAY) {
					overlays.put(i, block.getName());
					blockChooser.addItem(String.format("%s: 0x%08X-0x%08X", block.getName(), block.getStart().getOffset(), block.getEnd().getOffset()));
				}
			}
			
			if (overlays.size() > 0) {
				blockChooser.setSelectedIndex(0);
			}
			
			JPanel tablePanel = new JPanel(new BorderLayout());
			tablePanel.add(blockChooser);
			panel.add(tablePanel, BorderLayout.CENTER);
			
			setVisible(true);
		}

		private void createActions() {
			if (blockChooser.getItemCount() == 0) {
				return;
			}
			
			action = new DockingAction("PsxLoadOverlay", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					if (jfc.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
						try {
							FileInputStream fis = new FileInputStream(jfc.getSelectedFile().getAbsolutePath());
							byte[] fileData = fis.readAllBytes();
							
							int index = blockChooser.getSelectedIndex();
							MemoryBlock block = program.getMemory().getBlock(overlays.get(index));
							block.putBytes(block.getStart(), fileData);
							
							fis.close();
						} catch (IOException e) {
							Msg.showError(this, panel, "Error", "Cannot read overlay file!", e);
						} catch (MemoryAccessException e) {
							Msg.showError(this, panel, "Error", "Cannot set overlay block data!", e);
						}
					}
				}
				
				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return super.isEnabledForContext(context);
				}
			};
			action.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_TOOLS, "Load PSX Overlay..."}));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addAction(action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}

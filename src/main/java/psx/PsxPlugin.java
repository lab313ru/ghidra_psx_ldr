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
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;
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
	DockingAction action;

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
		action = new DockingAction("PsxLoadOverlay", getName()) {
			
			@Override
			public void actionPerformed(ActionContext context) {
				if (provider == null) {
					provider = new MyProvider(PsxPlugin.this, currentProgram);
				}
				
				if (provider.isVisible()) {
					provider.toFront();
				} else {
					provider.setVisible(true);
				}
			}
		};
		
		action.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_TOOLS, "PSX", "Load Overlay Binary..."}));
		tool.addAction(action);
	}

	private static class MyProvider extends ComponentProvider {

		private Program program;
		private JPanel panel;
		private JButton browse;
		private JComboBox<String> blockChooser = new JComboBox<>();
		private Map<Integer, String> overlays = new HashMap<>();

		public MyProvider(Plugin plugin, Program program) {
			super(plugin.getTool(), "PSX Overlay Loader", plugin.getName());
			this.program = program;
			
			buildPanel();
			addRefresh();
		}
		
		private void addRefresh() {
			DockingAction refreshAction = new DockingAction("PsxLoadOverlayRefresh", getName()) {
				
				@Override
				public void actionPerformed(ActionContext context1) {
					refreshBlocks();
				}
			};
			refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
			refreshAction.setDescription("Refreshes overlayed blocks list");
			
			this.getTool().addLocalAction(this, refreshAction);
		}
		
		private void refreshBlocks() {
			blockChooser.removeAllItems();
			overlays.clear();
			
			Memory mem = program.getMemory();
			MemoryBlock[] memBlocks = mem.getBlocks();
			for (MemoryBlock block : memBlocks) {
				if (block.getType() == MemoryBlockType.OVERLAY) {
					overlays.put(overlays.size(), block.getName());
					blockChooser.addItem(String.format("%s: 0x%08X-0x%08X", block.getName(), block.getStart().getOffset(), block.getEnd().getOffset()));
				}
			}
			
			browse.setEnabled(overlays.size() > 0);
		}

		private void buildPanel() {
			panel = new JPanel();
			panel.setLayout(new BorderLayout());
			
			JFileChooser jfc = new JFileChooser(program.getExecutablePath());
			jfc.setDialogTitle("Please, select overlay file...");
			jfc.setMultiSelectionEnabled(false);
			
			browse = new JButton("Choose overlay data...");
			
			refreshBlocks();
			
			if (overlays.size() > 0) {
				blockChooser.setSelectedIndex(0);
			}
			
			browse.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (jfc.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
						try {
							FileInputStream fis = new FileInputStream(jfc.getSelectedFile().getAbsolutePath());
							byte[] fileData = fis.readAllBytes();
							fis.close();
							
							int index = blockChooser.getSelectedIndex();
							Memory mem = program.getMemory();
							MemoryBlock block = mem.getBlock(overlays.get(index));
							
							int transId = program.startTransaction(String.format("Applying overlayed binary to %s", block.getName()));
							
							if (block.isInitialized()) {
								mem.convertToUninitialized(block);
							}
							mem.convertToInitialized(block, (byte) 0x00);
							mem.setBytes(block.getStart(), fileData);
							
							program.endTransaction(transId, true);
							
							Msg.showInfo(this, panel, "Information", "Overlay data has been applied!");
						} catch (IOException e1) {
							Msg.showError(this, panel, "Error", "Cannot read overlay file!", e1);
						} catch (MemoryAccessException | LockException | NotFoundException e2) {
							Msg.showError(this, panel, "Error", "Cannot set overlay block data!", e2);
						}
					}
				}
			});
			
			JPanel tablePanel = new JPanel(new VerticalLayout(10));
			tablePanel.add(blockChooser);
			tablePanel.add(browse);
			panel.add(tablePanel, BorderLayout.CENTER);
			panel.setMinimumSize(new Dimension(200, tablePanel.getPreferredSize().height + 50));
			
			setVisible(true);
		}
		
		@Override
		public void componentActivated() {
			super.componentActivated();
			refreshBlocks();
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}

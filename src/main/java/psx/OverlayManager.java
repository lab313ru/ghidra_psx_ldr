package psx;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import java.awt.GridBagLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.textfield.HexOrDecimalInput;
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.NamingUtilities;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.border.EmptyBorder;
import javax.swing.SwingConstants;
import javax.swing.JRadioButton;
import javax.swing.JComboBox;
import javax.swing.ButtonGroup;

public class OverlayManager extends JPanel {

	private final JLabel lblBlockName;
	private final JTextField blockName;
	private final JButton btnNewBlock;
	private final JLabel lblBlockStart;
	private final HexOrDecimalInput blockStart;
	private final DialogComponentProvider provider;
	private final Memory memory;
	private final Program program;
	private final JRadioButton chkNewBlock;
	private final JRadioButton chkFillBlock;
	private final JPanel pnlNewBlock;
	private final JComboBox<String> overlaysList;
	private final JButton btnFillBlock;
	private Map<Integer, String> overlays = new HashMap<>();
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private JRadioButton chkDeleteBlock;
	private JButton btnDeleteBlock;
	private int lastOvrIndex;
	
	/**
	 * Create the panel.
	 */
	public OverlayManager(Program program, DialogComponentProvider provider) {
		this.provider = provider;
		this.program = program;
		this.memory = program.getMemory();
		
		lastOvrIndex = 0;
		
		setBorder(new EmptyBorder(5, 5, 5, 5));
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{81, 110, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{1.0, 1.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		chkNewBlock = new JRadioButton("New Block");
		
		buttonGroup.add(chkNewBlock);
		GridBagConstraints gbc_createNewBlock = new GridBagConstraints();
		gbc_createNewBlock.anchor = GridBagConstraints.NORTHWEST;
		gbc_createNewBlock.insets = new Insets(0, 0, 5, 5);
		gbc_createNewBlock.gridx = 0;
		gbc_createNewBlock.gridy = 0;
		add(chkNewBlock, gbc_createNewBlock);
		
		chkFillBlock = new JRadioButton("Fill Block");
		GridBagConstraints gbc_chkFillBlock = new GridBagConstraints();
		gbc_chkFillBlock.anchor = GridBagConstraints.WEST;
		gbc_chkFillBlock.insets = new Insets(0, 0, 5, 5);
		gbc_chkFillBlock.gridx = 1;
		gbc_chkFillBlock.gridy = 0;
		add(chkFillBlock, gbc_chkFillBlock);
		buttonGroup.add(chkFillBlock);
		
		chkDeleteBlock = new JRadioButton("Delete Block");
		GridBagConstraints gbc_chkDeleteBlock = new GridBagConstraints();
		gbc_chkDeleteBlock.anchor = GridBagConstraints.WEST;
		gbc_chkDeleteBlock.insets = new Insets(0, 0, 5, 0);
		gbc_chkDeleteBlock.gridx = 2;
		gbc_chkDeleteBlock.gridy = 0;
		add(chkDeleteBlock, gbc_chkDeleteBlock);
		buttonGroup.add(chkDeleteBlock);
		
		pnlNewBlock = new JPanel();
		GridBagConstraints gbc_pnlNewBlock = new GridBagConstraints();
		gbc_pnlNewBlock.insets = new Insets(0, 0, 5, 0);
		gbc_pnlNewBlock.fill = GridBagConstraints.HORIZONTAL;
		gbc_pnlNewBlock.gridwidth = 3;
		gbc_pnlNewBlock.anchor = GridBagConstraints.NORTH;
		gbc_pnlNewBlock.gridx = 0;
		gbc_pnlNewBlock.gridy = 1;
		add(pnlNewBlock, gbc_pnlNewBlock);
		GridBagLayout gbl_pnlNewBlock = new GridBagLayout();
		gbl_pnlNewBlock.columnWidths = new int[]{72, 88, 0, 0, 0};
		gbl_pnlNewBlock.rowHeights = new int[]{0, 0, 0};
		gbl_pnlNewBlock.columnWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_pnlNewBlock.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		pnlNewBlock.setLayout(gbl_pnlNewBlock);
		
		lblBlockName = new JLabel("Block Name:");
		GridBagConstraints gbc_lblBlockName = new GridBagConstraints();
		gbc_lblBlockName.anchor = GridBagConstraints.EAST;
		gbc_lblBlockName.insets = new Insets(0, 0, 5, 5);
		gbc_lblBlockName.gridx = 0;
		gbc_lblBlockName.gridy = 0;
		pnlNewBlock.add(lblBlockName, gbc_lblBlockName);
		lblBlockName.setHorizontalAlignment(SwingConstants.RIGHT);
		
		blockName = new JTextField(null);
		updateOvrName(true);
		GridBagConstraints gbc_blockName = new GridBagConstraints();
		gbc_blockName.fill = GridBagConstraints.HORIZONTAL;
		gbc_blockName.insets = new Insets(0, 0, 5, 5);
		gbc_blockName.gridx = 1;
		gbc_blockName.gridy = 0;
		pnlNewBlock.add(blockName, gbc_blockName);
		blockName.setColumns(10);
		lblBlockName.setLabelFor(blockName);
		
		lblBlockStart = new JLabel("Start Address:");
		GridBagConstraints gbc_lblBlockStart = new GridBagConstraints();
		gbc_lblBlockStart.anchor = GridBagConstraints.EAST;
		gbc_lblBlockStart.insets = new Insets(0, 0, 5, 5);
		gbc_lblBlockStart.gridx = 2;
		gbc_lblBlockStart.gridy = 0;
		pnlNewBlock.add(lblBlockStart, gbc_lblBlockStart);
		lblBlockStart.setHorizontalAlignment(SwingConstants.RIGHT);
		
		blockStart = new HexOrDecimalInput();
		GridBagConstraints gbc_blockStart = new GridBagConstraints();
		gbc_blockStart.fill = GridBagConstraints.HORIZONTAL;
		gbc_blockStart.insets = new Insets(0, 0, 5, 0);
		gbc_blockStart.gridx = 3;
		gbc_blockStart.gridy = 0;
		pnlNewBlock.add(blockStart, gbc_blockStart);
		
		overlaysList = new JComboBox<String>();
		GridBagConstraints gbc_overlaysList = new GridBagConstraints();
		gbc_overlaysList.insets = new Insets(0, 0, 5, 0);
		gbc_overlaysList.fill = GridBagConstraints.HORIZONTAL;
		gbc_overlaysList.gridwidth = 3;
		gbc_overlaysList.gridx = 0;
		gbc_overlaysList.gridy = 2;
		add(overlaysList, gbc_overlaysList);
		
		btnNewBlock = new JButton("Create from a binary...");
		GridBagConstraints gbc_btnNewBlock = new GridBagConstraints();
		gbc_btnNewBlock.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnNewBlock.insets = new Insets(0, 0, 0, 5);
		gbc_btnNewBlock.gridx = 0;
		gbc_btnNewBlock.gridy = 3;
		add(btnNewBlock, gbc_btnNewBlock);
		
		btnFillBlock = new JButton("Fill with a binary...");
		GridBagConstraints gbc_btnFillBlock = new GridBagConstraints();
		gbc_btnFillBlock.insets = new Insets(0, 0, 0, 5);
		gbc_btnFillBlock.gridx = 1;
		gbc_btnFillBlock.gridy = 3;
		add(btnFillBlock, gbc_btnFillBlock);
		
		btnDeleteBlock = new JButton("Delete block");
		GridBagConstraints gbc_btnDeleteBlock = new GridBagConstraints();
		gbc_btnDeleteBlock.gridx = 2;
		gbc_btnDeleteBlock.gridy = 3;
		add(btnDeleteBlock, gbc_btnDeleteBlock);
		
		blockStart.setHexMode();
		blockStart.setAllowNegative(false);
		blockStart.setValue(program.getImageBase().getOffset());
		
		chkNewBlock.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				btnDeleteBlock.setEnabled(false);
				btnFillBlock.setEnabled(false);
				setEnabledNewBlock(true);
				
				checkNameAndAddress();
			}
		});
		
		chkFillBlock.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setEnabledNewBlock(false);
				btnDeleteBlock.setEnabled(false);
				setEnabledFillBlock();
			}
		});
		
		chkDeleteBlock.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setEnabledNewBlock(false);
				btnFillBlock.setEnabled(false);
				setEnabledDeleteBlock();
			}
		});
		
		setBlockNameListener();
		setBlockStartListener();
		setNewBlockListener();
		setFillBlockListener();
		setDeleteBlockListener();
		
		chkNewBlock.doClick();
		
		setMinimumSize(new Dimension(130, 50));
	}
	
	private void updateOvrName(boolean inc) {
		lastOvrIndex += inc ? 1 : -1;
		
		if (lastOvrIndex < 1) {
			lastOvrIndex = 1;
		}
		
		blockName.setText(String.format("OVR%d", lastOvrIndex));
	}
	
	private void setEnabledNewBlock(boolean enabled) {
		refreshOverlaysList();
		
		lblBlockName.setEnabled(enabled);
		blockName.setEnabled(enabled);
		lblBlockStart.setEnabled(enabled);
		blockStart.setEnabled(enabled);
		btnNewBlock.setEnabled(enabled);
		
		overlaysList.setEnabled(false);
	}
	
	private boolean refreshOverlaysList() {
		refreshBlocks();
		boolean more = overlays.size() > 0;
		overlaysList.setSelectedIndex(more ? 0 : -1);
		return more;
	}
	
	private void setEnabledFillBlock() {
		boolean more = refreshOverlaysList();
		btnFillBlock.setEnabled(more);
		
		overlaysList.setEnabled(more);
		btnFillBlock.setEnabled(more);
		provider.clearStatusText();
	}
	
	private void setEnabledDeleteBlock() {
		boolean more = refreshOverlaysList();
		
		overlaysList.setEnabled(more);
		btnDeleteBlock.setEnabled(more);
		provider.clearStatusText();
	}
	
	private void refreshBlocks() {
		overlaysList.removeAllItems();
		overlays.clear();

		MemoryBlock[] memBlocks = memory.getBlocks();
		for (MemoryBlock block : memBlocks) {
			if (block.isOverlay()) {
				overlays.put(overlays.size(), block.getName());
				overlaysList.addItem(String.format("%s: 0x%08X-0x%08X", block.getName(), block.getStart().getOffset(), block.getEnd().getOffset()));
			}
		}
	}
	
	private void checkNameAndAddress() {
		btnNewBlock.setEnabled(nameChanged() && addressChanged());
	}
	
	private boolean addressChanged() {
		btnNewBlock.setEnabled(false);
		long addr = blockStart.getValue();
		
		long ramBase = program.getImageBase().getOffset();

		if ((addr < ramBase) || (addr >= (ramBase + PsxLoader.RAM_SIZE))) {
			provider.setStatusText(String.format("An address must be in range: %08X-%08X", ramBase, ramBase + PsxLoader.RAM_SIZE - 1));
			return false;
		}
		
		provider.clearStatusText();
		return true;
	}
	
	private boolean nameChanged() {
		if (!chkNewBlock.isSelected()) {
			provider.clearStatusText();
			return false;
		}
		
		String name = blockName.getText().trim();
		
		if (name.isEmpty()) {
			provider.setStatusText("Please enter a name!");
			return false;
		} else if (!NamingUtilities.isValidProjectName(name)) {
			provider.setStatusText("Invalid block name!", MessageType.ERROR);
			return false;
		} else if (memory.getBlock(name) != null) {
			provider.setStatusText("Block name already exists!", MessageType.ERROR);
			return false;
		} else {
			provider.clearStatusText();
			return true;
		}
	}
	
	private void setBlockNameListener() {
		blockName.getDocument().addDocumentListener(new DocumentListener() {
			
			@Override
			public void removeUpdate(DocumentEvent e) {
				checkNameAndAddress();
			}
			
			@Override
			public void insertUpdate(DocumentEvent e) {
				checkNameAndAddress();
			}
			
			@Override
			public void changedUpdate(DocumentEvent e) {
				checkNameAndAddress();
			}
		});
	}
	
	private void setBlockStartListener() {
		blockStart.getDocument().addDocumentListener(new DocumentListener() {
			
			@Override
			public void removeUpdate(DocumentEvent e) {
				checkNameAndAddress();
			}
			
			@Override
			public void insertUpdate(DocumentEvent e) {
				checkNameAndAddress();
			}
			
			@Override
			public void changedUpdate(DocumentEvent e) {
				checkNameAndAddress();
			}
		});
	}

	private void setNewBlockListener() {
		JFileChooser jfc = new JFileChooser(program.getExecutablePath());
		jfc.setDialogTitle("Please, select overlay file...");
		jfc.setMultiSelectionEnabled(false);
		
		btnNewBlock.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (jfc.showOpenDialog(OverlayManager.this) != JFileChooser.APPROVE_OPTION) {
					return;
				}
				
				try {
					String filePath = jfc.getSelectedFile().getAbsolutePath();
					FileInputStream fis = new FileInputStream(filePath);
					byte[] fileData = fis.readAllBytes();
					fis.close();
					
					Memory mem = program.getMemory();
					AddressSpace defSpace = program.getAddressFactory().getDefaultAddressSpace();
					
					int tranId = program.startTransaction(String.format("Creating overlayed block %s from a binary", blockName.getText()));

					AddInitializedMemoryBlockCmd cmd = new AddInitializedMemoryBlockCmd(
							blockName.getText(), null, filePath, defSpace.getAddressInThisSpaceOnly(blockStart.getValue()),
							fileData.length,
							true, true, true, false, (byte) 0x00, true);
					cmd.applyTo(program);
					
					MemoryBlock block = mem.getBlock(blockName.getText());
					mem.setBytes(block.getStart(), fileData);
					
					program.endTransaction(tranId, true);
					
					MessageLog log = new MessageLog();
					long psxGpReg = PsxLoader.getGpBase(program);
					PsxLoader.setRegisterValue(program, "gp", block.getStart(), block.getEnd(), psxGpReg, log);
					
					refreshBlocks();
					checkNameAndAddress();
					updateOvrName(true);
					
					Msg.showInfo(this, OverlayManager.this, "Information", "Overlay block has been created!");
				} catch (IOException e1) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot read overlay file!", e1);
				} catch (MemoryAccessException e1) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot set block data!", e1);
				} catch (NoValueException e1) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot get GP value!", e1);
				}
			}
		});
	}
	
	private void setFillBlockListener() {
		JFileChooser jfc = new JFileChooser(program.getExecutablePath());
		jfc.setDialogTitle("Please, select overlay file...");
		jfc.setMultiSelectionEnabled(false);
		
		btnFillBlock.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (jfc.showOpenDialog(OverlayManager.this) != JFileChooser.APPROVE_OPTION) {
					return;
				}
				
				try {
					FileInputStream fis = new FileInputStream(jfc.getSelectedFile().getAbsolutePath());
					byte[] fileData = fis.readAllBytes();
					fis.close();
					
					int index = overlaysList.getSelectedIndex();
					MemoryBlock block = memory.getBlock(overlays.get(index));
					
					int transId = program.startTransaction(String.format("Applying overlayed binary to %s", block.getName()));
					
					if (block.isInitialized()) {
						memory.convertToUninitialized(block);
					}
					memory.convertToInitialized(block, (byte) 0x00);
					memory.setBytes(block.getStart(), fileData);
					
					program.endTransaction(transId, true);
					
					refreshBlocks();
					
					Msg.showInfo(this, OverlayManager.this, "Information", "Overlay data has been applied!");
				} catch (IOException e1) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot read overlay file!", e1);
				} catch (MemoryAccessException | LockException e2) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot set overlay block data!", e2);
				}
			}
		});
	}
	
	private void setDeleteBlockListener() {
		btnDeleteBlock.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				int index = overlaysList.getSelectedIndex();
				
				MemoryBlock block = memory.getBlock(overlays.get(index));
				
				if (block != null && OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null,
						"Question", String.format("Are you sure you want to delete %s block?", block.getName()))) {
					try {
						
						int transId = program.startTransaction(String.format("Removing block %s", block.getName()));
						memory.removeBlock(block, TaskMonitor.DUMMY);
						program.endTransaction(transId, true);

						updateOvrName(false);
						
						Msg.showInfo(this, OverlayManager.this, "Information", "Overlay block has been deleted!");
					} catch (LockException e1) {
						Msg.showError(this, OverlayManager.this, "Error", "Cannot remove memory block!", e1);
					}
				}
				
				setEnabledDeleteBlock();
			}
		});
	}
}

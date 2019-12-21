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
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.app.util.AddressInput;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.NamingUtilities;
import ghidra.util.exception.NotFoundException;

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
	private final AddressInput blockStart;
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
	
	/**
	 * Create the panel.
	 */
	public OverlayManager(Program program, DialogComponentProvider provider) {
		this.provider = provider;
		this.program = program;
		this.memory = program.getMemory();
		
		setBorder(new EmptyBorder(5, 5, 5, 5));
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{81, 110, 0};
		gridBagLayout.rowHeights = new int[]{29, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		chkNewBlock = new JRadioButton("New Block");
		chkNewBlock.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setEnabledFillBlock(false);
				setEnabledNewBlock(true);
			}
		});
		buttonGroup.add(chkNewBlock);
		chkNewBlock.setSelected(true);
		GridBagConstraints gbc_createNewBlock = new GridBagConstraints();
		gbc_createNewBlock.anchor = GridBagConstraints.NORTHWEST;
		gbc_createNewBlock.insets = new Insets(0, 0, 5, 5);
		gbc_createNewBlock.gridx = 0;
		gbc_createNewBlock.gridy = 0;
		add(chkNewBlock, gbc_createNewBlock);
		
		pnlNewBlock = new JPanel();
		GridBagConstraints gbc_pnlNewBlock = new GridBagConstraints();
		gbc_pnlNewBlock.gridheight = 2;
		gbc_pnlNewBlock.gridwidth = 2;
		gbc_pnlNewBlock.fill = GridBagConstraints.BOTH;
		gbc_pnlNewBlock.gridx = 0;
		gbc_pnlNewBlock.gridy = 1;
		add(pnlNewBlock, gbc_pnlNewBlock);
		GridBagLayout gbl_pnlNewBlock = new GridBagLayout();
		gbl_pnlNewBlock.columnWidths = new int[]{0, 121, 0, 0};
		gbl_pnlNewBlock.rowHeights = new int[]{0, 0, 0, 0, 0, 0};
		gbl_pnlNewBlock.columnWeights = new double[]{1.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_pnlNewBlock.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		pnlNewBlock.setLayout(gbl_pnlNewBlock);
		
		lblBlockName = new JLabel("Block Name:");
		GridBagConstraints gbc_lblBlockName = new GridBagConstraints();
		gbc_lblBlockName.insets = new Insets(0, 0, 5, 5);
		gbc_lblBlockName.anchor = GridBagConstraints.EAST;
		gbc_lblBlockName.gridx = 0;
		gbc_lblBlockName.gridy = 0;
		pnlNewBlock.add(lblBlockName, gbc_lblBlockName);
		lblBlockName.setHorizontalAlignment(SwingConstants.RIGHT);
		
		blockName = new JTextField();
		GridBagConstraints gbc_blockName = new GridBagConstraints();
		gbc_blockName.fill = GridBagConstraints.HORIZONTAL;
		gbc_blockName.insets = new Insets(0, 0, 5, 5);
		gbc_blockName.gridx = 1;
		gbc_blockName.gridy = 0;
		pnlNewBlock.add(blockName, gbc_blockName);
		blockName.setColumns(10);
		lblBlockName.setLabelFor(blockName);
		
		btnNewBlock = new JButton("Create from a binary...");
		GridBagConstraints gbc_browse = new GridBagConstraints();
		gbc_browse.insets = new Insets(0, 0, 5, 0);
		gbc_browse.anchor = GridBagConstraints.EAST;
		gbc_browse.fill = GridBagConstraints.VERTICAL;
		gbc_browse.gridheight = 2;
		gbc_browse.gridx = 2;
		gbc_browse.gridy = 0;
		pnlNewBlock.add(btnNewBlock, gbc_browse);
		
		lblBlockStart = new JLabel("Start Address:");
		GridBagConstraints gbc_lblBlockStart = new GridBagConstraints();
		gbc_lblBlockStart.anchor = GridBagConstraints.EAST;
		gbc_lblBlockStart.insets = new Insets(0, 0, 5, 5);
		gbc_lblBlockStart.gridx = 0;
		gbc_lblBlockStart.gridy = 1;
		pnlNewBlock.add(lblBlockStart, gbc_lblBlockStart);
		lblBlockStart.setHorizontalAlignment(SwingConstants.RIGHT);
		
		blockStart = new AddressInput();
		GridBagConstraints gbc_blockStart = new GridBagConstraints();
		gbc_blockStart.fill = GridBagConstraints.HORIZONTAL;
		gbc_blockStart.insets = new Insets(0, 0, 5, 5);
		gbc_blockStart.gridx = 1;
		gbc_blockStart.gridy = 1;
		pnlNewBlock.add(blockStart, gbc_blockStart);
		
		AddressFactory addrFactory = program.getAddressFactory();
		blockStart.setAddressFactory(addrFactory, true, false);
		blockStart.setAddress(program.getImageBase());
		
		chkFillBlock = new JRadioButton("Fill Block");
		GridBagConstraints gbc_chkFillBlock = new GridBagConstraints();
		gbc_chkFillBlock.anchor = GridBagConstraints.WEST;
		gbc_chkFillBlock.insets = new Insets(0, 0, 5, 5);
		gbc_chkFillBlock.gridx = 0;
		gbc_chkFillBlock.gridy = 2;
		pnlNewBlock.add(chkFillBlock, gbc_chkFillBlock);
		chkFillBlock.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setEnabledNewBlock(false);
				setEnabledFillBlock(true);
			}
		});
		buttonGroup.add(chkFillBlock);
		
		overlaysList = new JComboBox<String>();
		GridBagConstraints gbc_overlaysList = new GridBagConstraints();
		gbc_overlaysList.gridwidth = 2;
		gbc_overlaysList.fill = GridBagConstraints.HORIZONTAL;
		gbc_overlaysList.insets = new Insets(0, 0, 5, 5);
		gbc_overlaysList.gridx = 0;
		gbc_overlaysList.gridy = 3;
		pnlNewBlock.add(overlaysList, gbc_overlaysList);
		
		btnFillBlock = new JButton("Fill with a binary...");
		GridBagConstraints gbc_btnFillBlock = new GridBagConstraints();
		gbc_btnFillBlock.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnFillBlock.insets = new Insets(0, 0, 5, 0);
		gbc_btnFillBlock.gridx = 2;
		gbc_btnFillBlock.gridy = 3;
		pnlNewBlock.add(btnFillBlock, gbc_btnFillBlock);
		blockStart.addChangeListener(ev -> checkNameAndAddress());
		
		setBlockNameListener();
		setNewBlockListener();
		setFillBlockListener();
		
		chkNewBlock.doClick();
		
		setMinimumSize(new Dimension(220, 50));
	}
	
	private void setEnabledNewBlock(boolean enabled) {
		lblBlockName.setEnabled(enabled);
		blockName.setEnabled(enabled);
		lblBlockStart.setEnabled(enabled);
		blockStart.setEnabled(enabled);
		btnNewBlock.setEnabled(enabled);
		
		checkNameAndAddress();
	}
	
	private void setEnabledFillBlock(boolean enabled) {
		refreshBlocks();
		overlaysList.setSelectedIndex((overlays.size() > 0) ? 0 : -1);
		
		overlaysList.setEnabled(enabled);
		btnFillBlock.setEnabled(enabled);
		provider.clearStatusText();
	}
	
	private void refreshBlocks() {
		overlaysList.removeAllItems();
		overlays.clear();

		MemoryBlock[] memBlocks = memory.getBlocks();
		for (MemoryBlock block : memBlocks) {
			if (block.getType() == MemoryBlockType.OVERLAY) {
				overlays.put(overlays.size(), block.getName());
				overlaysList.addItem(String.format("%s: 0x%08X-0x%08X", block.getName(), block.getStart().getOffset(), block.getEnd().getOffset()));
			}
		}
		
		btnFillBlock.setEnabled(overlays.size() > 0);
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
					
					Msg.showInfo(this, OverlayManager.this, "Information", "Overlay data has been applied!");
				} catch (IOException e1) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot read overlay file!", e1);
				} catch (MemoryAccessException | LockException | NotFoundException e2) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot set overlay block data!", e2);
				}
			}
		});
	}
	
	private void checkNameAndAddress() {
		btnNewBlock.setEnabled(nameChanged() && addressChanged());
	}
	
	private boolean addressChanged() {
		btnNewBlock.setEnabled(false);
		Address addr = null;

		try {
			addr = blockStart.getAddress();
		}
		catch (IllegalArgumentException ignored) {
		}
		
		if (addr == null) {
			provider.setStatusText("Please enter a valid starting address", MessageType.ERROR);
			return false;
		}
		
		if ((addr.getOffset() < PsxLoader.ramBase) || (addr.getOffset() >= (PsxLoader.ramBase + PsxLoader.RAM_SIZE))) {
			provider.setStatusText(String.format("An address must be in range: %08X-%08X", PsxLoader.ramBase, PsxLoader.ramBase + PsxLoader.RAM_SIZE - 1));
			return false;
		}
		
		blockStart.setAddress(addr);
		provider.clearStatusText();
		return true;
	}
	
	private boolean nameChanged() {
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

					int tranId = program.startTransaction(String.format("Create overlayed block %s from a binary", blockName.getText()));
					AddInitializedMemoryBlockCmd cmd = new AddInitializedMemoryBlockCmd(
							blockName.getText(), null, filePath, blockStart.getAddress(),
							fileData.length,
							true, true, true, false, (byte) 0x00, true);
					cmd.applyTo(program);
					program.endTransaction(tranId, true);
					
					Msg.showInfo(this, OverlayManager.this, "Information", "Overlay block has been created!");
					refreshBlocks();
				} catch (IOException e1) {
					Msg.showError(this, OverlayManager.this, "Error", "Cannot read overlay file!", e1);
				}
			}
		});
	}
}

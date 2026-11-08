package psx;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;

import ghidra.app.util.AddressFactoryService;
import ghidra.app.util.importer.options.StringOption;

public class PsxSizeChooser extends StringOption {

	private final static String[] items = new String[] {
			"0x200000",  // 2 MB - retail console
			"0x400000",  // 4 MB - arcade board
			"0x800000",  // 8 MB - development kit
			"0x1000000", // 16 MB - arcade board
	};

	private final JComboBox<String> editor = new JComboBox<>(items);

	public PsxSizeChooser(String name, String value, String arg) {
		super(name, value, arg, null, null, false, null);

		int sel = 0;
		for (int i = 0; i < items.length; ++i) {
			if (items[i].equals(value)) {
				sel = i;
				break;
			}
		}

		editor.setSelectedIndex(sel);
		setValue(items[sel]);

		editor.addItemListener(new ItemListener() {

			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
						PsxSizeChooser.this.setValue((String)e.getItem());
			       }
			}

		});

		editor.setEditable(false);
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		return editor;
	}

	@Override
	public PsxSizeChooser copy() {
		return new PsxSizeChooser(getName(), getValue(), getArg());
	}
}

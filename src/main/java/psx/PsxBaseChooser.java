package psx;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;

import ghidra.app.util.AddressFactoryService;
import ghidra.app.util.importer.options.StringOption;

public class PsxBaseChooser extends StringOption {

	private final static String[] items = new String[] {
			"0x80000000",
			"0x00000000",
			"0xA0000000",
	};

	private final JComboBox<String> editor = new JComboBox<>(items);

	public PsxBaseChooser(String name, String value, String arg) {
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
						PsxBaseChooser.this.setValue((String)e.getItem());
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
	public PsxBaseChooser copy() {
		return new PsxBaseChooser(getName(), getValue(), getArg());
	}
}

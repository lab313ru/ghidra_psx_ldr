package psx;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;

import ghidra.app.util.Option;

public class PsxSizeChooser extends Option {

	private String selected;
	private String[] items = new String[] {
			"0x200000",  // 2 MB - retail console
			"0x400000",  // 4 MB - arcade board
			"0x800000",  // 8 MB - development kit
			"0x1000000", // 16 MB - arcade board
	};

	private JComboBox<String> editor = new JComboBox<>(items);

	public PsxSizeChooser(String name, Object value, Class<?> valueClass, String arg) {
		super(name, valueClass, value, arg, null);

		selected = items[0];

		editor.addItemListener(new ItemListener() {

			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
						selected = (String)e.getItem();
						PsxSizeChooser.super.setValue(selected);
			       }
			}

		});

		editor.setEditable(false);
	}

	@Override
	public Component getCustomEditorComponent() {
		return editor;
	}

	@Override
	public Option copy() {
		return new PsxSizeChooser(getName(), getValue(), getValueClass(), getArg());
	}

	@Override
	public Object getValue() {
		return selected;
	}

	@Override
	public Class<?> getValueClass() {
		return String.class;
	}
}

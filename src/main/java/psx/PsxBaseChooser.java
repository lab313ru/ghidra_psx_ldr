package psx;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JComboBox;

import ghidra.app.util.Option;

public class PsxBaseChooser extends Option {
	
	private String selected;
	private String[] items = new String[] {
			"0x80000000",
			"0x00000000",
			"0xA0000000",
	};
	
	private JComboBox<String> editor = new JComboBox<>(items);

	public PsxBaseChooser(String name, Object value, Class<?> valueClass, String arg) {
		super(name, valueClass, value, arg, null);
		
		selected = items[0];
		
		editor.addItemListener(new ItemListener() {

			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
						selected = (String)e.getItem();
						PsxBaseChooser.super.setValue(selected);
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
		return new PsxBaseChooser(getName(), getValue(), getValueClass(), getArg());
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

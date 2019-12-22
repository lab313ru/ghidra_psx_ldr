package psx;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import resources.ResourceManager;

public class DebuggerProvider extends ComponentProviderAdapter {

	private final static ImageIcon ICON = ResourceManager.loadImage("images/debug_icon.png");
	private final DebuggerGui gui;
	
	public DebuggerProvider(PluginTool tool, String name) {
		super(tool, name, name);

		gui = new DebuggerGui();
		
		setIcon(ICON);
		setDefaultWindowPosition(WindowPosition.RIGHT);
		setTitle("PSX Debugger");
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return gui;
	}
}

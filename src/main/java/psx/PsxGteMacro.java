package psx;

public final class PsxGteMacro {
	private final String name;
	private final String[] args;
	
	public PsxGteMacro(final String name, final String[] args) {
		this.name = name;
		this.args = args.clone();
	}
	
	public String getName() {
		return name;
	}
	
	public String[] getArgs() {
		return args;
	}
}

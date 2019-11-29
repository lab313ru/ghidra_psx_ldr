package psyq.sym;

public class SymTypedef extends SymObject {
	private final SymDef base;
	
	public SymTypedef(SymDef base) {
		super(0L);
		
		this.base = base;
	}
	
	public String getName() {
		return base.getName();
	}

	public SymDef getDefinition() {
		return base;
	}
}

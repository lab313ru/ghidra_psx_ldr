package psyq.sym;

public class SymTypedef extends SymObject {
	private final SymDef base;
	
	public SymTypedef(SymDef base) {
		super(0L);
		
		this.base = base;
	}
	
	public String getBaseName() {
		String defTag = base.getDefTag();
		return (defTag == null || defTag.isEmpty()) ? base.getName() : defTag;
	}
	
	public String getTypedefName() {
		return base.getName();
	}

	public SymDef getDefinition() {
		return base;
	}
}

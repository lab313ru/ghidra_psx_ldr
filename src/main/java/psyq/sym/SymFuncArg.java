package psyq.sym;

public class SymFuncArg {
	private final SymDefClass argClass;
	private final String argType;
	private final int argSize; 
	
	public SymFuncArg(SymDefClass argClass, String argType, int argSize) {
		this.argClass = argClass;
		this.argType = argType;
		this.argSize = argSize;
	}

	public SymDefClass getArgClass() {
		return argClass;
	}

	public String getArgType() {
		return argType;
	}

	public int getArgSize() {
		return argSize;
	}
}

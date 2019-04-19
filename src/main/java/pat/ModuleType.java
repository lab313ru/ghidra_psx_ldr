package pat;

public enum ModuleType {
	GLOBAL_NAME, LOCAL_NAME, REF_NAME;

	public boolean isGlobal() {
		return this == GLOBAL_NAME;
	}
	
	private boolean isLocal() {
		return this == LOCAL_NAME;
	}
	
	public boolean isReference() {
		return this == REF_NAME;
	}
	
	@Override
	public String toString() {
		if (isGlobal()) {
			return "Global";
		} else if (isLocal()) {
			return "Local";
		} else {
			return "Reference";
		}
	}
}

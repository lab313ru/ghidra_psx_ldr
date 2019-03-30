package pat;

public class ModuleData {

	private final long offset;
	private final String name;
	private final ModuleType type;
	
	public ModuleData(long offset, String name, ModuleType type) {
		this.offset = offset;
		this.name = name;
		this.type = type;
	}

	public final long getOffset() {
		return offset;
	}

	public final String getName() {
		return name;
	}
	
	public final ModuleType getType() {
		return type;
	}
}

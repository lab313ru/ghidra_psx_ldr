package psyq.structs;

public final class Definition {
	private final int section;
	private final long value;
	private final int classIndex;
	private final int type;
	private final long size;
	private final String name;
	
	public final int getSection() {
		return section;
	}

	public final long getValue() {
		return value;
	}

	public final int getClassIndex() {
		return classIndex;
	}

	public final int getType() {
		return type;
	}

	public final long getSize() {
		return size;
	}

	public final String getName() {
		return name;
	}

	public Definition(int section, long value, int classIndex, int type, long size, String name) {
		this.section = section;
		this.value = value;
		this.classIndex = classIndex;
		this.type = type;
		this.size = size;
		this.name = name;
	}
}

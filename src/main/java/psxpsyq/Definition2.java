package psxpsyq;

import java.util.List;

public final class Definition2 {
	private final int section;
	private final long value;
	private final int classIndex;
	private final int type;
	private final long size;
	private final int dims;
	private final List<Long> longs;
	private final String tag;
	private final String tag2;
	
	public final int getDims() {
		return dims;
	}

	public final List<Long> getLongs() {
		return longs;
	}

	public final String getTag() {
		return tag;
	}

	public final String getTag2() {
		return tag2;
	}
	
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

	public Definition2(int section, long value, int classIndex, int type, long size, List<Long> longs, String tag, String tag2) {
		this.section = section;
		this.value = value;
		this.classIndex = classIndex;
		this.type = type;
		this.size = size;
		this.dims = longs.size();
		this.longs = longs;
		this.tag = tag;
		this.tag2 = tag2;
	}
}

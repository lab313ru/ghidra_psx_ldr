package psxpsyq;

public final class XbssSymbol extends Symbol {
	private final int sectionIndex;

	public final int getSectionIndex() {
		return sectionIndex;
	}

	public XbssSymbol(int number, String name, long address, long length, int sectionIndex) {
		super(number, name, address, length);
		this.sectionIndex = sectionIndex;
	}
}

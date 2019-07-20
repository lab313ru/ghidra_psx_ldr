package psxpsyq;

public final class LocalSymbol extends Symbol {
	private final int sectionIndex;
	
	public LocalSymbol(String name, long address, int sectionIndex) {
		super(1, name, address, 0);
		this.sectionIndex = sectionIndex;
	}

	public final int getSectionIndex() {
		return sectionIndex;
	}
}

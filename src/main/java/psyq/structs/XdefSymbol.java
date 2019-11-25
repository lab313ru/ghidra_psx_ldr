package psyq.structs;

public final class XdefSymbol extends Symbol {
	private final int sectionIndex;
	
	public XdefSymbol(int number, String name, long address, int sectionIndex) {
		super(number, name, address, 0);
		this.sectionIndex = sectionIndex;
	}

	public final int getSectionIndex() {
		return sectionIndex;
	}
}

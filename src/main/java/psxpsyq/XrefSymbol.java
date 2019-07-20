package psxpsyq;

public final class XrefSymbol extends Symbol {
	private final int sectionIndex;
	
	public XrefSymbol(int number, String name, long address, int sectionIndex) {
		super(number, name, address, 4);
		
		this.sectionIndex = sectionIndex;
	}
	
	public int getSectionIndex() {
		return sectionIndex;
	}
}

package psyq.structs;

public final class XrefSymbol extends Symbol {
	private final int sectionIndex;
	private final boolean isXbss;
	
	public XrefSymbol(int number, String name, long address, long size, boolean isXbss, int sectionIndex) {
		super(number, name, address, size);
		
		this.isXbss = isXbss;
		this.sectionIndex = sectionIndex;
	}
	
	public int getSectionIndex() {
		return sectionIndex;
	}
	
	public boolean isXbssSymbol() {
		return isXbss;
	}
}

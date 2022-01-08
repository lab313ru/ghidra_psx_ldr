package psx;

public class PsxUpdateAddressSpacesOverride {
	private final String funcAddr;
	private final int lineNum;
	private final String symAddr;
	
	public PsxUpdateAddressSpacesOverride(String funcAddr, int lineNum, String symAddr) {
		this.funcAddr = funcAddr;
		this.lineNum = lineNum;
		this.symAddr = symAddr;
	}
	
	public String getFunctionAddress() {
		return funcAddr;
	}
	
	public int getLineNumber() {
		return lineNum;
	}
	
	public String getSymbolAddress() {
		return symAddr;
	}
}

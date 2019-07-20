package psxpsyq;

public abstract class Symbol implements ISymbol {
	private final int number;
	private final String name;
	private long address;
	private final long length;
	
	public Symbol(int number, String name, long address, long length) {
		this.number = number;
		this.name = name;
		this.address = address;
		this.length = length;
	}
	
	@Override
	public int getNumber() {
		return number;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public long getAddress() {
		return address;
	}
	
	@Override
	public void setAddress(long address) {
		this.address = address;
	}
	
	@Override
	public long getLength() {
		return length;
	}
}

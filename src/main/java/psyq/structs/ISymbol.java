package psyq.structs;

public interface ISymbol {
	public int getNumber();

	public String getName();
	
	public long getAddress();
	
	public void setAddress(long address);
	
	public long getLength();
}

package psyq.sym;

public class SymName extends SymObject {
	String name;
	
	public SymName(long offset, String name) {
		super(offset);
		
		this.name = name;
	}
	
	public String getObjectName() {
		return name;
	}
}

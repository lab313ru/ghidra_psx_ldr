package psyq.sym;

public class SymName extends SymObject {
	String name;
	
	public SymName(long offset, int tag, String name) {
		super(offset, tag);
		this.name = name;
	}
	
	public String getObjectName() {
		return name;
	}
}

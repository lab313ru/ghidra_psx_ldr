package psyq.sym;

public class SymObjectName extends SymObject {
	String name;
	
	public SymObjectName(long offset, byte tag, String name) {
		super(offset, tag);
		this.name = name;
	}
	
	public String getObjectName() {
		return name;
	}
}

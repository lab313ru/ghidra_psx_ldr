package psyq.sym;

public class SymName extends SymObject {
	String name;
	
	public SymName(String name, long offset, long overlayId) {
		super(offset, overlayId);
		
		this.name = name;
	}
	
	public String getObjectName() {
		return name;
	}
}

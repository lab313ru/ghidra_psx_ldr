package psyq.sym;

public class SymName extends SymObject {
	private String name;
	
	public SymName(String name, long offset, long overlayId) {
		super(offset, overlayId);
		
		this.name = name;
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String newName) {
		name = newName;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof SymName)) {
			return false;
		}
		
		return name.equals(((SymName)obj).name);
	}
	
	@Override
	public int hashCode() {
		return name.hashCode();
	}
}

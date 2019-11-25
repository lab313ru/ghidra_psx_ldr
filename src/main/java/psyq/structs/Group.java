package psyq.structs;

public final class Group extends Symbol {
	private final byte type;
	
	public Group(int number, String name, byte type) {
		super(number, name, 0, 0);
		this.type = type;
	}
	
	public final byte getType() {
		return type;
	}
}

package psyq.sym;

public class SymSld extends SymObject {
	private long line;
	
	public SymSld(long offset, byte tag, long line) {
		super(offset, tag);
		
		this.line = line;
	}
	
	public long getLineIndex() {
		return line;
	}
}

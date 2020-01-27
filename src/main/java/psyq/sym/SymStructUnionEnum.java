package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymStructUnionEnum extends SymName {
	private final long size;
	private final boolean isFake;
	private final SymDefTypePrim type;
	
	private final List<SymDef> fields = new ArrayList<>();
	
	private final static String FAKE_R = "\\.(\\d+)fake";
	
	public SymStructUnionEnum(String name, long size, SymDefTypePrim type) {
		super(name, 0L, 0L);
		
		this.name = name;
		this.isFake = name.matches(FAKE_R);
		this.size = size;
		this.type = type;
	}
	
	public void addField(SymDef field) {
		this.fields.add(field);
	}
	
	public SymDef toSymDef() {
		SymDefClass cl;
		
		switch (type) {
		case STRUCT: cl = SymDefClass.STRTAG; break;
		case UNION: cl = SymDefClass.UNTAG; break;
		case ENUM: cl = SymDefClass.ENTAG; break;
		default: return null;
		}
		
		return new SymDef(cl, new SymDefType(new SymDefTypePrim[] {type}), false, size, name, getOffset(), getOverlayId());
	}

	@Override
	public String getName() {
		return isFake ? getFakeStructUnionEnumName(name, type) : name;
	}
	
	private static String getFakeStructUnionEnumName(String name, SymDefTypePrim type) {
		return name;
	}

	public boolean isFake() {
		return isFake;
	}
	
	public long getSize() {
		return size;
	}
	
	public SymDefTypePrim getType() {
		return type;
	}

	public SymDef[] getFields() {
		return fields.toArray(SymDef[]::new);
	}
}

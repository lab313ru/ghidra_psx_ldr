package psyq.sym;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SymStructUnionEnum extends SymObject {
	private final String name;
	private final long size;
	private final boolean isFake;
	private final SymDefTypePrimitive type;
	
	private final List<SymDef> fields = new ArrayList<>();
	
	private final static String FAKE_R = "\\.(\\d+)fake";
	
	public SymStructUnionEnum(String name, long size, SymDefTypePrimitive type) {
		super(0L);
		
		this.name = name;
		this.isFake = name.matches(FAKE_R);
		this.size = size;
		this.type = type;
	}
	
	public void addField(SymDef field) {
		this.fields.add(field);
	}

	public String getName() {
		return isFake ? getFakeStructUnionEnumName(name, type) : name;
	}
	
	private static String getFakeStructUnionEnumName(String name, SymDefTypePrimitive type) {
		Pattern pat = Pattern.compile(FAKE_R);
		Matcher mat = pat.matcher(name);
		
		if (mat.find()) {
			switch (type) {
			case UNION: return String.format("FakeUnion%0d", mat.group(1));
			case ENUM: return String.format("FakeEnum%0d", mat.group(1));
			default: return String.format("FakeStruct%0d", mat.group(1));
			}
		}
		
		return name;
	}

	public boolean isFake() {
		return isFake;
	}
	
	public long getSize() {
		return size;
	}
	
	public SymDefTypePrimitive getType() {
		return type;
	}

	public SymDef[] getFields() {
		return fields.toArray(SymDef[]::new);
	}
}

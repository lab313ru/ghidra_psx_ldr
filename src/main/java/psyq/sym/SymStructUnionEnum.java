package psyq.sym;

import java.util.ArrayList;
import java.util.List;

public class SymStructUnionEnum extends SymName {
	private final long size;
	private final SymTypePrimitive type;
	
	private final List<SymDefinition> fields = new ArrayList<>();
	
	public SymStructUnionEnum(String name, long size, SymTypePrimitive type) {
		super(name, 0L, 0L);

		this.size = size;
		this.type = type;
	}
	
	public void addField(SymDefinition field) {
		this.fields.add(field);
	}
	
	public long getSize() {
		return size;
	}
	
	public SymTypePrimitive getType() {
		return type;
	}

	public SymDefinition[] getFields() {
		return fields.toArray(SymDefinition[]::new);
	}
}

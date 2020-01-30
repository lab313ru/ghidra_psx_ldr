package psyq.sym;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SymType {
	private List<SymTypePrimitive> primTypes = new ArrayList<>();
	
	public SymType(SymTypePrimitive[] primTypes) {
		Collections.addAll(this.primTypes, primTypes);
	}
	
	public SymType(int type) {
		while ((type & 0xFFF0) != 0) {
			int type1 = (type >> 4) & 3;

			switch (type1) {
			case 1: primTypes.add(SymTypePrimitive.PTR); break;
			case 2: primTypes.add(SymTypePrimitive.FCN); break;
			case 3: primTypes.add(SymTypePrimitive.ARY); break;
			}

			type = ((type >> 2) & 0xFFF0) + (type & 0xF);
		}

		switch (type)
		{
		case 0:	primTypes.add(SymTypePrimitive.NULL); break;
		case 1: primTypes.add(SymTypePrimitive.VOID); break;
		case 2:	primTypes.add(SymTypePrimitive.CHAR); break;
		case 3:	primTypes.add(SymTypePrimitive.SHORT); break;
		case 4:	primTypes.add(SymTypePrimitive.INT); break;
		case 5:	primTypes.add(SymTypePrimitive.LONG); break;
		case 6:	primTypes.add(SymTypePrimitive.FLOAT); break;
		case 7:	primTypes.add(SymTypePrimitive.DOUBLE); break;
		case 8:	primTypes.add(SymTypePrimitive.STRUCT); break;
		case 9:	primTypes.add(SymTypePrimitive.UNION); break;
		case 10: primTypes.add(SymTypePrimitive.ENUM); break;
		case 11: primTypes.add(SymTypePrimitive.MOE); break;
		case 12: primTypes.add(SymTypePrimitive.UCHAR); break;
		case 13: primTypes.add(SymTypePrimitive.USHORT); break;
		case 14: primTypes.add(SymTypePrimitive.UINT); break;
		case 15: primTypes.add(SymTypePrimitive.ULONG); break;
		}
	}
	
	public SymTypePrimitive getPrimaryType() {
		return (primTypes.size() > 0) ? primTypes.get(0) : SymTypePrimitive.NULL;
	}
	
	public SymTypePrimitive[] getTypesList() {
		return primTypes.toArray(SymTypePrimitive[]::new);
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		
		for (int i = primTypes.size() - 1; i >= 0 ; --i) {
			builder.append(primTypes.get(i).name()).append(' ');
		}
		
		return builder.toString();
	}
}

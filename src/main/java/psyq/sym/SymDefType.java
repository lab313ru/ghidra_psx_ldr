package psyq.sym;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SymDefType {
	private List<SymDefTypePrim> primTypes = new ArrayList<>();
	
	public SymDefType(SymDefTypePrim[] primTypes) {
		Collections.addAll(this.primTypes, primTypes);
	}
	
	public SymDefType(int type) {
		while ((type & 0xFFF0) != 0) {
			int type1 = (type >> 4) & 3;

			switch (type1) {
			case 1: primTypes.add(SymDefTypePrim.PTR); break;
			case 2: primTypes.add(SymDefTypePrim.FCN); break;
			case 3: primTypes.add(SymDefTypePrim.ARY); break;
			}

			type = ((type >> 2) & 0xFFF0) + (type & 0xF);
		}

		switch (type)
		{
		case 0:	primTypes.add(SymDefTypePrim.NULL); break;
		case 1: primTypes.add(SymDefTypePrim.VOID); break;
		case 2:	primTypes.add(SymDefTypePrim.CHAR); break;
		case 3:	primTypes.add(SymDefTypePrim.SHORT); break;
		case 4:	primTypes.add(SymDefTypePrim.INT); break;
		case 5:	primTypes.add(SymDefTypePrim.LONG); break;
		case 6:	primTypes.add(SymDefTypePrim.FLOAT); break;
		case 7:	primTypes.add(SymDefTypePrim.DOUBLE); break;
		case 8:	primTypes.add(SymDefTypePrim.STRUCT); break;
		case 9:	primTypes.add(SymDefTypePrim.UNION); break;
		case 10: primTypes.add(SymDefTypePrim.ENUM); break;
		case 11: primTypes.add(SymDefTypePrim.MOE); break;
		case 12: primTypes.add(SymDefTypePrim.UCHAR); break;
		case 13: primTypes.add(SymDefTypePrim.USHORT); break;
		case 14: primTypes.add(SymDefTypePrim.UINT); break;
		case 15: primTypes.add(SymDefTypePrim.ULONG); break;
		}
	}
	
	public SymDefTypePrim[] getTypesList() {
		return primTypes.toArray(SymDefTypePrim[]::new);
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

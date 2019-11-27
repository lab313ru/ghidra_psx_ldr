package psyq.sym;

import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;

public class SymDef extends SymObject {
	private SymDefClass defClass;
	private SymDefType defType;
	private long size;
	private String name;
	
	private Long[] dims;
	private String defTag;
	
	public SymDef(SymDefClass defClass, SymDefType defType, long size, String name, long offset) {
		super(offset, (byte)0x94);
		
		this.defClass = defClass;
		this.defType = defType;
		this.size = size;
		this.name = name;
		this.dims = null;
		this.defTag = null;
	}

	public SymDefClass getDefClass() {
		return defClass;
	}

	public SymDefType getDefType() {
		return defType;
	}

	public long getSize() {
		return size;
	}

	public String getName() {
		return name;
	}
	
	public void setDims(Long[] dims) {
		this.dims = dims.clone();
	}
	
	public void setDefTag(String defTag) {
		this.defTag = defTag;
	}
	
	public Long[] getDims() {
		return dims;
	}
	
	public String getDefTag() {
		return defTag;
	}
	
	public static DataType toDataType(SymDefTypePrimitive[] primTypes, String defTag, DataTypeManager mgr) throws Exception {
		if (primTypes.length == 0) {
			return null;
		}
		
		SymDefTypePrimitive type = primTypes[0];
		
		if (primTypes.length == 1 || (primTypes.length == 2 && type == SymDefTypePrimitive.FCN)) {
			if (type == SymDefTypePrimitive.FCN) {
				type = primTypes[1];
			}
			
			switch (type) {
			case VOID: return DataType.VOID;
			case CHAR: return CharDataType.dataType;
			case SHORT: return ShortDataType.dataType;
			case INT: return IntegerDataType.dataType;
			case LONG: return LongDataType.dataType;
			case FLOAT: return FloatDataType.dataType;
			case DOUBLE: return DoubleDataType.dataType;
			case UCHAR: return UnsignedCharDataType.dataType;
			case USHORT: return UnsignedShortDataType.dataType;
			case UINT: return UnsignedIntegerDataType.dataType;
			case ULONG: return UnsignedLongDataType.dataType;
			default: throw new Exception("Invalid single primitive data type");
			}
		}
		
		switch (type) {
		case PTR: {
			SymDefTypePrimitive ptrType = primTypes[1];
			
			switch (ptrType) {
			case VOID: return new PointerDataType(DataType.VOID);
			case CHAR: return new PointerDataType(CharDataType.dataType);
			case SHORT: return new PointerDataType(ShortDataType.dataType);
			case INT: return new PointerDataType(IntegerDataType.dataType);
			case LONG: return new PointerDataType(LongDataType.dataType);
			case FLOAT: return new PointerDataType(FloatDataType.dataType);
			case DOUBLE: return new PointerDataType(DoubleDataType.dataType);
			case UCHAR: return new PointerDataType(UnsignedCharDataType.dataType);
			case USHORT: return new PointerDataType(UnsignedShortDataType.dataType);
			case UINT: return new PointerDataType(UnsignedIntegerDataType.dataType);
			case ULONG: return new PointerDataType(UnsignedLongDataType.dataType);
			
			case STRUCT: return (mgr == null || defTag == null) ? null : mgr.getDataType(mgr.getRootCategory().getCategoryPath(), defTag);
			
			default: return null;
			}
		}
		default: return null;
		}
	}
}

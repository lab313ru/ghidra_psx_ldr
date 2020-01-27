package psyq.sym;

import java.util.Arrays;

import ghidra.program.model.data.ArrayDataType;
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

public class SymDef extends SymName {
	private final SymDefClass defClass;
	private final SymDefType defType;
	private final long size;
	
	private Integer[] dims;
	private final boolean hasTag;
	private String tag;
	
	public SymDef(SymDefClass defClass, SymDefType defType, boolean hasTag, long size, String name, long offset, long overlayId) {
		super(name, offset, overlayId);
		
		this.defClass = defClass;
		this.defType = defType;
		this.size = size;
		this.name = name;
		this.dims = null;
		this.hasTag = hasTag;
		this.tag = null;
	}

	public SymDefClass getDefClass() {
		return defClass;
	}

	public SymDefType getDefType() {
		return defType;
	}
	
	public DataType getDataType(DataTypeManager mgr) {
		SymDefTypePrim[] types = defType.getTypesList();
		
		if (types.length == 0) {
			return DataType.VOID;
		}
		
		return primTypeToDataType(types, dims, mgr);
	}
	
	private DataType primTypeToDataType(SymDefTypePrim[] types, Integer[] newDims, DataTypeManager mgr) {
		switch (types[0]) {
		case PTR: {
			SymDefTypePrim[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			DataType ptrTo = primTypeToDataType(followTypes, newDims, mgr);
			
			if (ptrTo != null) {
				return new PointerDataType(ptrTo);
			}

			return null;
		}
		case FCN: {
			SymDefTypePrim[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			return primTypeToDataType(followTypes, newDims, mgr);
		}
		case ARY: {
			SymDefTypePrim[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			Integer[] followDims = Arrays.copyOfRange(newDims, 1, newDims.length);
			DataType arrItemType = primTypeToDataType(followTypes, followDims, mgr);
			
			if (arrItemType == null) {
				return null;
			}

			if (newDims[0] == 0) {
				newDims[0] = 1;
			}
			
			return new ArrayDataType(arrItemType, newDims[0], arrItemType.getLength());
		}
		case VOID: return DataType.VOID;
		case CHAR: return new CharDataType();
		case SHORT: return new ShortDataType();
		case INT: return new IntegerDataType();
		case LONG: return new LongDataType();
		case FLOAT: return new FloatDataType();
		case DOUBLE: return new DoubleDataType();
		case STRUCT:
		case UNION:
		case ENUM: {
			DataType dt = mgr.getDataType(mgr.getRootCategory().getCategoryPath(), hasTag ? tag : name);
			
			if (dt != null) {
				return dt;
			}

			return null;
		}
		case UCHAR: return new UnsignedCharDataType();
		case USHORT: return new UnsignedShortDataType();
		case UINT: return new UnsignedIntegerDataType();
		case ULONG: return new UnsignedLongDataType();
		default: return new IntegerDataType();
		}
	}

	public long getSize() {
		return size;
	}
	
	public void setDims(Integer[] dims) {
		this.dims = dims.clone();
	}
	
	public void setTag(String tag) {
		this.tag = tag;
	}
	
	public String getTag() {
		return tag;
	}
	
	public Integer[] getDims() {
		return dims;
	}
	
	public boolean hasTag() {
		return hasTag;
	}
}

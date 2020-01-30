package psyq.sym;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

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

public class SymDefinition extends SymName {
	private final SymClass _class;
	private final SymType _type;
	private final long size;
	
	private Integer[] dims;
	private String tag;
	
	public SymDefinition(SymDefinition def) {
		this(def._class, def._type, def.tag, def.dims, def.size, def.getName(), def.getOffset(), def.getOverlayId());
	}
	
	public SymDefinition(SymClass symClass, SymType symType, String tag, Integer[] dims, long size, String name, long offset, long overlayId) {
		super(name, offset, overlayId);
		
		this._class = symClass;
		this._type = symType;
		this.size = size;
		this.dims = dims;
		this.tag = tag;
	}

	public SymClass getSymClass() {
		return _class;
	}

	public SymType getSymType() {
		return _type;
	}
	
	public DataType getDataType(final Map<SymDataTypeManagerType, DataTypeManager> mgrs) {
		SymTypePrimitive[] types = _type.getTypesList();
		
		if (types.length == 0) {
			return DataType.VOID;
		}
		
		return primitiveTypeToDataType(types, dims, mgrs);
	}
	
	public SymStructUnionEnum getBaseStructOrUnion() {
		SymTypePrimitive[] types = _type.getTypesList();
		
		if (types.length == 0) {
			return null;
		}
		
		for (SymTypePrimitive tp : types) {
			if (tp == SymTypePrimitive.STRUCT || tp == SymTypePrimitive.UNION) {
				return new SymStructUnionEnum(tag, size, tp);
			}
		}
		
		return null;
	}
	
	private DataType primitiveTypeToDataType(SymTypePrimitive[] types, Integer[] newDims, final Map<SymDataTypeManagerType, DataTypeManager> mgrs) {
		switch (types[0]) {
		case PTR: {
			SymTypePrimitive[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			DataType ptrTo = primitiveTypeToDataType(followTypes, newDims, mgrs);
			
			if (ptrTo != null) {
				return new PointerDataType(ptrTo);
			}

			return null;
		}
		case FCN: {
			SymTypePrimitive[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			return primitiveTypeToDataType(followTypes, newDims, mgrs);
		}
		case ARY: {
			SymTypePrimitive[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			Integer[] followDims = Arrays.copyOfRange(newDims, 1, newDims.length);
			DataType arrItemType = primitiveTypeToDataType(followTypes, followDims, mgrs);
			
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
			for (DataTypeManager mgr : mgrs.values()) {
				DataType dt = hasDataTypeName(mgr, (tag != null) ? tag : getName());
				if (dt != null) {
					return dt;
				}
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
	
	public static DataType hasDataTypeName(DataTypeManager mgr, String name) {
		Iterator<DataType> ss = mgr.getAllDataTypes();
		
		while (ss.hasNext()) {
			DataType dt = ss.next();
			if (dt.getName().equals(name)) {
				return dt;
			}
		}
		
		return null;
	}
	
//	
//	@Override
//    protected SymDefinition clone() throws CloneNotSupportedException {
//        return (SymDefinition)super.clone();
//    }
}

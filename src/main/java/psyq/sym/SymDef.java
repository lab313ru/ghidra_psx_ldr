package psyq.sym;

import java.util.Arrays;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;

public class SymDef extends SymObject {
	private final SymDefClass defClass;
	private final SymDefType defType;
	private final long size;
	private String name;
	
	private Integer[] dims;
	private String defTag;
	
	public SymDef(SymDefClass defClass, SymDefType defType, long size, String name, long offset) {
		super(offset);
		
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
	
	public DataType getDataType(DataTypeManager mgr) {
		SymDefTypePrim[] types = defType.getTypesList();
		
		if (types.length == 0) {
			return DataType.VOID;
		}
		
		return primTypeToDataType(types, name, defTag, (int)size, dims, mgr);
	}
	
	private static DataType primTypeToDataType(SymDefTypePrim[] types,
			String name, String defTag,
			int size, Integer[] dims, DataTypeManager mgr) {
		
		switch (types[0]) {
		case PTR: {
			SymDefTypePrim[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			DataType ptrTo = primTypeToDataType(followTypes, name, defTag, size, dims, mgr);
			return new PointerDataType(ptrTo);
		}
		case FCN: {
			SymDefTypePrim[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			return primTypeToDataType(followTypes, name, defTag, size, dims, mgr);
		}
		case ARY: {
			SymDefTypePrim[] followTypes = Arrays.copyOfRange(types, 1, types.length);
			Integer[] followDims = Arrays.copyOfRange(dims, 1, dims.length);
			DataType arrItemType = primTypeToDataType(followTypes, name, defTag, size, followDims, mgr);
			return new ArrayDataType(arrItemType, dims[0], arrItemType.getLength());
		}
		case VOID: return DataType.VOID;
		case CHAR: return new CharDataType();
		case SHORT: return new ShortDataType();
		case INT: return new IntegerDataType();
		case LONG: return new LongDataType();
		case FLOAT: return new FloatDataType();
		case DOUBLE: return new DoubleDataType();
		case STRUCT: {
			DataType dt = mgr.getDataType(mgr.getRootCategory().getCategoryPath(), defTag);
			
			if (dt != null) {
				return dt;
			}
			
			dt = mgr.getDataType(mgr.getRootCategory().getCategoryPath(), name);
			return (dt != null) ? dt : new StructureDataType(name, size);
		}
		case UNION: {
			DataType dt = mgr.getDataType(mgr.getRootCategory().getCategoryPath(), defTag);
			
			if (dt != null) {
				return dt;
			}
			
			dt = mgr.getDataType(mgr.getRootCategory().getCategoryPath(), name);
			return (dt != null) ? dt : new UnionDataType(name);
		}
		case ENUM: {
			DataType dt = mgr.getDataType(mgr.getRootCategory().getCategoryPath(), defTag);
			
			if (dt != null) {
				return dt;
			}
			
			dt = mgr.getDataType(mgr.getRootCategory().getCategoryPath(), name);
			return (dt != null) ? dt : new EnumDataType(name, size);
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
	
	public void setName(String newName) {
		this.name = newName;
	}

	public String getName() {
		return name;
	}
	
	public void setDims(Integer[] dims) {
		this.dims = dims.clone();
	}
	
	public void setDefTag(String defTag) {
		this.defTag = defTag;
	}
	
	public Integer[] getDims() {
		return dims;
	}
	
	public String getDefTag() {
		return defTag;
	}
}

package psyq.sym;

import java.io.File;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;

public class SymFile {
	private List<SymObject> objects = new ArrayList<>();
	
	public static SymFile fromBinary(String path) {
		try {
			ByteProvider provider = new RandomAccessByteProvider(new File(path));
			BinaryReader reader = new BinaryReader(provider, true);
			return new SymFile(reader);
		} catch (IOException e) {
			return null;
		}
	}

	private SymFile(BinaryReader reader) throws IOException {
		String sig = reader.readNextNullTerminatedAsciiString();
		
		if (!sig.equals("MND")) {
			throw new IOException("Wrong MND signature");
		}
		
		reader.readNextByte(); // version
		reader.readNextByte(); // unit
		reader.readNextByteArray(3); // skip
		
		SymFunc symFunc = null;
		List<SymFuncArg> funcArgs = new ArrayList<>();
		
		while (true) {
			long offset = 0;
			byte tag = 0;

			while (true) {
				offset = reader.readNextUnsignedInt();
				tag = reader.readNextByte();
				
				if (tag != 8) {
					break;
				}
				
				reader.readNextByte(); // MX-info
			}
			
			if (tag <= 0x7F) {
				String name = reader.readNextAsciiString();
				SymObject obj = new SymObjectName(offset, tag, name);
				objects.add(obj);
				continue;
			}
			
			switch (tag) {
			case (byte)0x80: {
			} break;
			case (byte)0x82: {
				reader.readNextByte(); // line byte_add
			} break;
			case (byte)0x84: {
				reader.readNextUnsignedShort(); // line word_add
			} break;
			case (byte)0x86: {
				reader.readNextUnsignedInt(); // new line_num
			} break;
			case (byte)0x88: {
				reader.readNextUnsignedInt(); // new line_num
				reader.readNextAsciiString(); // new line_num to file_name
			} break;
			case (byte)0x8A: {
			} break;
			case (byte)0x8C: {
				reader.readNextUnsignedShort(); // fp
				reader.readNextUnsignedInt(); // fsize
				reader.readNextUnsignedShort(); // retreg
				reader.readNextUnsignedInt(); // mask
				reader.readNextUnsignedInt(); // maskoffs
				reader.readNextUnsignedInt(); // line
				String fileName = reader.readNextAsciiString();
				String funcName = reader.readNextAsciiString();
				
				symFunc = new SymFunc(fileName, funcName, offset);
				
				// blocks
				// args
				// end line
			} break;
			case (byte)0x8E: {
				reader.readNextUnsignedInt(); // func end line
				if (symFunc == null) {
					throw new IOException("End of non-started function");
				}
				
				symFunc.setEndOffset(offset);
				objects.add(symFunc);
				symFunc = null;
				funcArgs.clear();
			} break;
			case (byte)0x90: {
				reader.readNextUnsignedInt(); // block start line
			} break;
			case (byte)0x92: {
				reader.readNextUnsignedInt(); // block end line
			} break;
			case (byte)0x94: {
				int classDefType1 = reader.readNextUnsignedShort();
			} break;
				
			}
		}
	}
	
	private static SymFuncArg getArgType() {
		return null;
	}
}

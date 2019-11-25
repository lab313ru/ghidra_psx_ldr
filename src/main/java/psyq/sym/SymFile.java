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
		
		long line_num = 0;
		
		while (true) {
			long bin_pos = 0;
			long offset = 0;
			byte tag = 0;
			
			SymSrcFile srcFile = null;
			SymFunc symFunc = null;
			ArrayDeque<SymFuncBlock> funcBlocks = null;
			
			while (true) {
				while (true) {
					bin_pos = reader.getPointerIndex();
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
					SymSld sld = new SymSld(offset, tag, ++line_num);
					
					if (srcFile == null) {
						throw new IOException("SLD file was not created before");
					}
					srcFile.addLine(sld);
				} break;
				case (byte)0x82: {
					byte byte_add = reader.readNextByte();
					line_num += byte_add;
					SymSld sld = new SymSld(offset, tag, line_num);
					
					if (srcFile == null) {
						throw new IOException("SLD file was not created before");
					}
					srcFile.addLine(sld);
				} break;
				case (byte)0x84: {
					int word_add = reader.readNextUnsignedShort();
					line_num += word_add;
					SymSld sld = new SymSld(offset, tag, line_num);
					
					if (srcFile == null) {
						throw new IOException("SLD file was not created before");
					}
					srcFile.addLine(sld);
				} break;
				case (byte)0x86: {
					line_num = reader.readNextUnsignedInt();
					SymSld sld = new SymSld(offset, tag, line_num);
					
					if (srcFile == null) {
						throw new IOException("SLD file was not created before");
					}
					srcFile.addLine(sld);
				} break;
				case (byte)0x88: {
					line_num = reader.readNextUnsignedInt();
					String file_name = reader.readNextAsciiString();
					SymSld sld = new SymSld(offset, tag, line_num);
					
					srcFile = new SymSrcFile(file_name, offset);
					srcFile.addLine(sld);
				} break;
				case (byte)0x8A: {
					srcFile.setEndOffset(offset);
					objects.add(srcFile);
					srcFile = null;
				} break;
				case (byte)0x8C: {
					int fp = reader.readNextUnsignedShort();
					long fsize = reader.readNextUnsignedInt();
					int retreg = reader.readNextUnsignedShort();
					long mask = reader.readNextUnsignedInt();
					long maskoffs = reader.readNextUnsignedInt();
					long line = reader.readNextUnsignedInt();
					String fileName = reader.readNextAsciiString();
					String funcName = reader.readNextAsciiString();
					
					symFunc = new SymFunc(fp, fsize, retreg, mask, maskoffs, line, fileName, funcName, offset);
					
					if (funcBlocks == null) {
						funcBlocks = new ArrayDeque<>();
					}
					
					// blocks
					// args
					// end line
				} break;
				case (byte)0x8E: {
					symFunc.setEndOffset(offset);
					objects.add(symFunc);
					symFunc = null;
				} break;
				case (byte)0x90: {
					long startLine = reader.readNextUnsignedInt();
					SymFuncBlock block = new SymFuncBlock(startLine, offset);
					
					if (funcBlocks == null) {
						throw new IOException("Block hasn't corresponding function");
					}
					
					funcBlocks.add(block);
				} break;
				case (byte)0x92: {
					long endLine = reader.readNextUnsignedInt();
					
					if (funcBlocks == null) {
						throw new IOException("Block hasn't corresponding function");
					}
					
					try {
						SymFuncBlock block = funcBlocks.getLast();
						block.setEndLineAndOffset(endLine, offset);
					} catch (NoSuchElementException e) {
						throw new IOException("Block hasn't start line");
					}
				} break;
				}
			}
		}
	}
}

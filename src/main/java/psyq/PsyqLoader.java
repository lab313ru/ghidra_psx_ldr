/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package psyq;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;

import static java.util.stream.Collectors.*;

import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.app.plugin.core.reloc.InstructionStasher;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import psx.PsxLoader;
import psx.Utils;
import psyq.structs.*;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class PsyqLoader extends AbstractLibrarySupportLoader {
	
	private HashMap<Integer, Long> runPoints = new HashMap<>();
	private int sectionSwitch = 0;
	private List<PatchInfo> patches = new ArrayList<>();
	private List<XdefSymbol> xdefs = new ArrayList<>();
	private HashMap<Integer, Symbol> symbols = new HashMap<>();
	private HashMap<Integer, XrefSymbol> xrefs = new HashMap<>();
	private HashMap<Integer, Section> sections = new HashMap<>();
	private List<LocalSymbol> locals = new ArrayList<>();
	private List<Group> groups = new ArrayList<>();
	private List<RegisterPatch> regPatches = new ArrayList<>();
	private List<DefinedFile> defFiles = new ArrayList<>();
	private FileLine fileLine = new FileLine();
	private List<LocalSymbol> vlocals = new ArrayList<>();
	private HashMap<Integer, Byte> mxInfos = new HashMap<>();
	private HashMap<Integer, List<XbssSymbol>> xbssList = new HashMap<>();
	private List<RepeatedData> repeatedData = new ArrayList<>();
	private List<FunctionStart> functionStarts = new ArrayList<>();
	private List<FunctionEnd> functionEnds = new ArrayList<>();
	private List<BlockStart> blockStarts = new ArrayList<>();
	private List<BlockEnd> blockEnds = new ArrayList<>();
	private List<Definition> defs = new ArrayList<>();
	private List<Definition2> defs2 = new ArrayList<>();

	@Override
	public String getName() {
		return "Psx PsyQ Object Files Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		
		String tag = reader.readAsciiString(0, 3);
		if (tag.equals("LNK")) {
			int version = reader.readByte(3);
			
			if (version == 2) {
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(PsxLoader.PSX_LANG_ID, "default"), true));
			}
		}

		return loadSpecs;
	}
	
	public static String detectPsyqFileVersion(final String path, String[] libObjName, String[] foundFile) {
		final File currFile = new File(path);
		final File currDir = currFile.getParentFile();
		
		File [] files = currDir.listFiles(new FilenameFilter() {
		    @Override
		    public boolean accept(File dir, String name) {
		        return name.startsWith("PSYQ_");
		    }
		});
		
		if (foundFile != null) {
			foundFile[0] = null;
		}
		
		String infoFile = "";
		
		if (files.length > 0) {
			infoFile = files[0].getName();
		}
		
		if (infoFile.isEmpty()) {
			return null;
		}
		
		var libRegex = Pattern.compile("^PSYQ(_LIB\\w+)?(_\\w+)$");
		var matcher = libRegex.matcher(infoFile);
		
		if (!matcher.matches()) {
			return null;
		}
		
		if (foundFile != null) {
			foundFile[0] = infoFile;
		}
		
		final String prefix = matcher.group(1);
		
		if (libObjName != null) {
			if (prefix != null) {
				libObjName[0] = String.format("%s.LIB", prefix.substring(1));
			} else {
				libObjName[0] = currFile.getName().toUpperCase();
			}
		}
		
		return matcher.group(2).substring(1);
	}
	
	private List<JsonArray> loadXbssList(final String libPath) throws FileNotFoundException, IOException {
		String[] libObjName = new String[1];
		final String version = detectPsyqFileVersion(libPath, libObjName, null);
		
		if (version == null) {
			return null;
		}
			
		final String psyDir = String.format("psyq/%s", version);
		final File verDir = Application.getModuleDataSubDirectory(psyDir).getFile(false);
		
		List<JsonArray> possibleObjs = new ArrayList<>();
		
		final var json = Utils.jsonArrayFromFile(String.format("%s/%s.json", verDir.getAbsolutePath(), libObjName[0]));
		
		for (final var item : json) {
			final var itemObj = item.getAsJsonObject();

			if (!itemObj.has("xbss")) {
				continue;
			}
			
			possibleObjs.add(itemObj.getAsJsonArray("xbss"));
		}
		
		return possibleObjs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		Options aOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		aOpts.setBoolean("Non-Returning Functions - Discovered", false);
		
		SymbolTable symTbl = program.getSymbolTable();
		Listing listing = program.getListing();
		
		String libObjPath = program.getExecutablePath();
		var root = provider.getFSRL();
		
		while (root != null) {
			root = root.getFS().getContainer();
			
			if (root != null) {
				libObjPath = root.getPath();
			}
		}
		
		final var objsXbss = loadXbssList(libObjPath);
		
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(4);
		
		monitor.clearCanceled();

		while (true) {
			if (monitor.isCancelled()) {
				break;
			}
			
			byte type = reader.readNextByte();
			
			boolean isEndOfFile = false;
			switch (type) {
			case 0: {
				isEndOfFile = true;
			} break;
			case 2: {
				int codeSize = reader.readNextUnsignedShort();
				byte[] bytes = reader.readNextByteArray(codeSize);
				
				Section sect = sections.get(sectionSwitch);
				
				ByteArrayOutputStream prev = new ByteArrayOutputStream();
				byte[] prevBytes = sect.getBytes();
				
				if (prevBytes != null) {
					prev.write(prevBytes);
				}
				
				prev.write(bytes);

				sect.setBytes(prev.toByteArray());
			} break;
			case 4: {
				int startSection = reader.readNextUnsignedShort();
				long startOffset = reader.readNextUnsignedInt();
				
				runPoints.put(startSection, startOffset);
			} break;
			case 6: {
				sectionSwitch = reader.readNextUnsignedShort();
			} break;
			case 8: {
				Section sect = sections.get(sectionSwitch);
				byte[] bytes = new byte[(int)reader.readNextUnsignedInt()];
				
				ByteArrayOutputStream prev = new ByteArrayOutputStream();
				
				byte[] oldBytes = sect.getBytes();
				
				if (oldBytes != null) {
					prev.write(oldBytes);
				}
				
				prev.write(bytes);

				sect.setBytes(prev.toByteArray());
			} break;
			case 10: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				patches.add(patchInfo);
			} break;
			case 12: {
				int symIndex = reader.readNextUnsignedShort();
				int sectIndex = reader.readNextUnsignedShort();
				long offset = reader.readNextUnsignedInt();
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				XdefSymbol sym = new XdefSymbol(symIndex, name, offset, sectIndex);
				xdefs.add(sym);
				symbols.put(symIndex, sym);
			} break;
			case 14: {
				int symIndex = reader.readNextUnsignedShort();
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				Section imps = sections.getOrDefault(Section.importsSectionIndex, new Section(Section.importsSectionIndex, Section.importsSectionName, 0, (byte) 8));
				sections.put(imps.getNumber(), imps);
				
				long symSize = 0x1000;
				boolean found = false;
				
				if (objsXbss != null) {
					for (final var objXbss : objsXbss) {
						for (final var item : objXbss) {
							final var itemObj = item.getAsJsonObject();
							
							if (itemObj.get("name").getAsString().equals(name)) {
								symSize = itemObj.get("size").getAsLong();
								found = true;
								break;
							}
						}
						
						if (found) {
							break;
						}
					}
				}
				
				long delta = symSize % imps.getAlignment();
				if (delta != 0L) {
					symSize += imps.getAlignment() - delta;
				}
				
				long prevLength = (int)xrefs.values().stream().mapToLong(XrefSymbol::getLength).sum();
				
				XrefSymbol sym = new XrefSymbol(symIndex, name, prevLength, symSize, found, Section.importsSectionIndex);
				xrefs.put(symIndex, sym);
				symbols.put(symIndex, sym);
			} break;
			case 16: {
				int symIndex = reader.readNextUnsignedShort();
				int groupIndex = reader.readNextUnsignedShort();
				byte align = reader.readNextByte();
				
				String name = reader.readNextAsciiString(reader.readNextByte());

				Section sym = new Section(symIndex, name, groupIndex, align);
				sections.put(symIndex, sym);
				symbols.put(symIndex, sym);
			} break;
			case 18: {
				int sectionIndex = reader.readNextUnsignedShort();
				long offset = reader.readNextUnsignedInt();
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				locals.add(new LocalSymbol(name, offset, sectionIndex));
			} break;
			case 20: {
				int groupIndex = reader.readNextUnsignedShort();
				byte groupType = reader.readNextByte();
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				groups.add(new Group(groupIndex, name, groupType));
			} break;
			case 22: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				int offset = reader.readNextUnsignedShort();
				RegisterPatch patch = new RegisterPatch(1, patchInfo, offset);
				
				regPatches.add(patch);
			} break;
			case 24: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				int offset = reader.readNextUnsignedShort();
				RegisterPatch patch = new RegisterPatch(2, patchInfo, offset);
				
				regPatches.add(patch);
			} break;
			case 26: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				int offset = reader.readNextUnsignedShort();
				RegisterPatch patch = new RegisterPatch(4, patchInfo, offset);
				
				regPatches.add(patch);
			} break;
			case 28: {
				int fileIndex = reader.readNextUnsignedShort();
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				defFiles.add(new DefinedFile(fileIndex, name));
			} break;
			case 30: {
				int fileIndex = reader.readNextUnsignedShort();
				long lineIndex = reader.readNextUnsignedInt();
				fileLine = new FileLine(fileIndex, lineIndex);
			} break;
			case 32: {
				fileLine.setLineIndex(reader.readNextUnsignedInt());
			} break;
			case 34: {
				fileLine.setLineIndex(fileLine.getLineIndex() + 1);
			} break;
			case 36: {
				fileLine.setLineIndex(fileLine.getLineIndex() + reader.readNextByte());
			} break;
			case 38: {
				fileLine.setLineIndex(fileLine.getLineIndex() + reader.readNextUnsignedShort());
			} break;
			case 40: {
				int sectionIndex = reader.readNextUnsignedShort();
				long offset = reader.readNextUnsignedInt();
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				vlocals.add(new LocalSymbol(name, offset, sectionIndex));
			} break;
			case 42: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				int offset = reader.readNextUnsignedShort();
				RegisterPatch patch = new RegisterPatch(3, patchInfo, offset);
				
				regPatches.add(patch);
			} break;
			case 44: {
				byte mxInfoVal = reader.readNextByte();
				int mxOffset = reader.readNextUnsignedShort();
				
				mxInfos.put(mxOffset, mxInfoVal);
			} break;
			case 46: {
				reader.readNextByte();
			} break;
			case 48: {
				int symIndex = reader.readNextUnsignedShort();
				int sectionIndex = reader.readNextUnsignedShort();
				long symSize = reader.readNextUnsignedInt();
				
				Section sect = sections.getOrDefault(sectionIndex, null);
				
				long delta = symSize % sect.getAlignment();
				if (delta != 0L) {
					symSize += sect.getAlignment() - delta;
				}
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				List<XbssSymbol> prevList = xbssList.getOrDefault(sectionIndex, new ArrayList<>());
				long prevLength = (int)prevList.stream().mapToLong(XbssSymbol::getLength).sum();
				
				XbssSymbol sym = new XbssSymbol(symIndex, name, prevLength, symSize, sectionIndex);
				prevList.add(sym);
				xbssList.put(sectionIndex, prevList);
				symbols.put(symIndex, sym);
			} break;
			case 50: {
				reader.readNextUnsignedShort(); // offset
			} break;
			case 52: {
				reader.readNextUnsignedShort(); // offset
				reader.readNextByte(); // val
			} break;
			case 54: {
				reader.readNextUnsignedShort(); // offset
				reader.readNextUnsignedShort(); // val
			} break;
			case 56: {
				reader.readNextUnsignedShort(); // offset
				reader.readNextUnsignedInt(); // val
			} break;
			case 58: {
				reader.readNextUnsignedShort(); // offset
				reader.readNextUnsignedInt(); // val
				reader.readNextUnsignedShort(); // fileIndex
			} break;
			case 60: {
				reader.readNextUnsignedShort();
			} break;
			case 62: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				long count = reader.readNextUnsignedInt();
				RepeatedData rep = new RepeatedData(patchInfo, count, 1);
				repeatedData.add(rep);
			} break;
			case 64: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				long count = reader.readNextUnsignedInt();
				RepeatedData rep = new RepeatedData(patchInfo, count, 2);
				repeatedData.add(rep);
			} break;
			case 66: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				long count = reader.readNextUnsignedInt();
				RepeatedData rep = new RepeatedData(patchInfo, count, 4);
				repeatedData.add(rep);
			} break;
			case 68: {
			} break;
			case 70: {
			} break;
			case 72: {
				int patchOffset = sections.get(sectionSwitch).getPatchOffset();
				PatchInfo patchInfo = new PatchInfo(patchOffset, sectionSwitch, reader, log);
				long count = reader.readNextUnsignedInt();
				RepeatedData rep = new RepeatedData(patchInfo, count, 3);
				repeatedData.add(rep);
			} break;
			case 74: {
				int section = reader.readNextUnsignedShort();
				long offset = reader.readNextUnsignedInt();
				int file = reader.readNextUnsignedShort();
				long startLine = reader.readNextUnsignedInt();
				int frameReg = reader.readNextUnsignedShort();
				long frameSize = reader.readNextUnsignedInt();
				int retnPcReg = reader.readNextUnsignedShort();
				long mask = reader.readNextUnsignedInt();
				long maskOffset = reader.readNextUnsignedInt();
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				FunctionStart func = new FunctionStart(section, offset, file, startLine, frameReg, frameSize, retnPcReg, mask, maskOffset, name);
				functionStarts.add(func);
			} break;
			case 76: {
				int section = reader.readNextUnsignedShort();
				long offset = reader.readNextUnsignedInt();
				long endLine = reader.readNextUnsignedInt();
				
				FunctionEnd func = new FunctionEnd(section, offset, endLine);
				functionEnds.add(func);
			} break;
			case 78: {
				int section = reader.readNextUnsignedShort();
				long offset = reader.readNextUnsignedInt();
				long startLine = reader.readNextUnsignedInt();
				
				BlockStart block = new BlockStart(section, offset, startLine);
				blockStarts.add(block);
			} break;
			case 80: {
				int section = reader.readNextUnsignedShort();
				long offset = reader.readNextUnsignedInt();
				long endLine = reader.readNextUnsignedInt();
				
				BlockEnd block = new BlockEnd(section, offset, endLine);
				blockEnds.add(block);
			} break;
			case 82: {
				int section = reader.readNextUnsignedShort();
				long value = reader.readNextUnsignedInt();
				int classIndex = reader.readNextUnsignedShort();
				int typeIndex = reader.readNextUnsignedShort();
				long size = reader.readNextUnsignedInt();
				
				Section sect = sections.getOrDefault(section, null);
				
				long delta = size % sect.getAlignment();
				if (delta != 0L) {
					size += sect.getAlignment() - delta;
				}
				
				String name = reader.readNextAsciiString(reader.readNextByte());
				
				Definition def = new Definition(section, value, classIndex, typeIndex, size, name);
				defs.add(def);
			} break;
			case 84: {
				int section = reader.readNextUnsignedShort();
				long value = reader.readNextUnsignedInt();
				int classIndex = reader.readNextUnsignedShort();
				int typeIndex = reader.readNextUnsignedShort();
				long size = reader.readNextUnsignedInt();
				int dims = reader.readNextUnsignedShort();
				
				Section sect = sections.getOrDefault(section, null);
				
				long delta = size % sect.getAlignment();
				if (delta != 0L) {
					size += sect.getAlignment() - delta;
				}
				
				List<Long> longs = new ArrayList<>();
				for (int i = 0; i < dims; ++i) {
					longs.add(reader.readNextUnsignedInt());
				}
				
				String tag = reader.readNextAsciiString(reader.readNextByte());
				String tag2 = reader.readNextAsciiString(reader.readNextByte());
				
				Definition2 def = new Definition2(section, value, classIndex, typeIndex, size, longs, tag, tag2);
				defs2.add(def);
			} break;
			default: {
				log.appendException(new Exception(String.format("%d : Unknown tag", type)));
				return;
			}
			}
			
			if (isEndOfFile) {
				break;
			}
		}
		
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);
		
		for (Integer sectionIndex : xbssList.keySet()) {
			List<XbssSymbol> sectXbss = xbssList.get(sectionIndex);

			Section sect = sections.get(sectionIndex);
			long length = (int)sectXbss.stream().mapToLong(XbssSymbol::getLength).sum();
			sect.setBytes(new byte[(int)length]);
			sections.put(sectionIndex, sect);
		}

		if (xrefs.size() > 0) {
			Section importsSect = sections.get(Section.importsSectionIndex);
			long length = (int)xrefs.values().stream().mapToLong(XrefSymbol::getLength).sum();
			importsSect.setBytes(new byte[(int)length]);
			sections.put(importsSect.getNumber(), importsSect);
		}
		
		List<Section> sortedSections = sections.entrySet().stream()
			    .sorted(Comparator.comparing(Map.Entry::getKey))
			    .filter(p -> p.getValue().getLength() > 0L)
			    .map(Map.Entry::getValue)
			    .collect(toList());
		
		for (Section sect : sortedSections) {
			sect.doAlign();
		}
		
		long lastOffset = 0x10100L;
		for (Section sect : sortedSections) {
			sect.setAddress(lastOffset);
			lastOffset += sect.getLength();
		}
		
		for (XdefSymbol xdef : xdefs) {
			long address = sections.get(xdef.getSectionIndex()).getAddress() + xdef.getAddress();
			xdef.setAddress(address);
			
			for (Section sect : sections.values()) {
				if (sect.getName().equals(".sdata")) {
					RegisterValue value = new RegisterValue(program.getRegister("gp"), BigInteger.valueOf(sect.getAddress()));
					Address start = fpa.toAddr(address);
					try {
						program.getProgramContext().setRegisterValue(start, start, value);
					} catch (ContextChangeException e) {
						log.appendException(e);
						return;
					}
					break;
				}
			}
		}
		
		for (XrefSymbol xref : xrefs.values()) {
			xref.setAddress(sections.get(xref.getSectionIndex()).getAddress() + xref.getAddress());
		}
		
		for (List<XbssSymbol> xbss_ : xbssList.values()) {
			for (XbssSymbol xbss : xbss_) {
				xbss.setAddress(sections.get(xbss.getSectionIndex()).getAddress() + xbss.getAddress());
			}
		}
		
		for (LocalSymbol local : locals) {
			local.setAddress(sections.get(local.getSectionIndex()).getAddress() + local.getAddress());
		}
		
		for (LocalSymbol vlocal : vlocals) {
			vlocal.setAddress(sections.get(vlocal.getSectionIndex()).getAddress() + vlocal.getAddress());
		}
		
		for (Section sect : sortedSections) {
			String name = sect.getName();
			Address start = fpa.toAddr(sect.getAddress());
			try {
				byte[] bytes = sect.getBytes();
				
				MemoryBlock block;
				
				block = fpa.createMemoryBlock(name, start, bytes, false);
				
				switch (name) {
				case ".rdata": {
					block.setRead(true);
					block.setExecute(false);
					block.setWrite(false);
					block.setVolatile(false);
				} break;
				case ".imps": {
					block.setRead(true);
					block.setExecute(false);
					block.setWrite(true);
					block.setVolatile(false);
				} break;
				case ".text": {
					block.setRead(true);
					block.setWrite(false);
					block.setExecute(true);
					block.setVolatile(false);
				} break;
				case ".data":
				case ".sdata":
				case ".sbss":
				case ".bss":
				case ".ctors":
				case ".dtors": {
					block.setRead(true);
					block.setWrite(true);
					block.setExecute(false);
					block.setVolatile(false);
				} break;
				default: {
					block.setRead(true);
					block.setWrite(true);
					block.setExecute(true);
					block.setVolatile(false);
				} break;
				}
			} catch (Exception e) {
				log.appendException(e);
				return;
			}
		}
		
		for (XdefSymbol xdef : xdefs) {
			Address offset = fpa.toAddr(xdef.getAddress());
			try {
				symTbl.createLabel(offset, xdef.getName(), SourceType.ANALYSIS);
			} catch (InvalidInputException e) {
				log.appendException(e);
				return;
			}
			
			DisassembleCommand dism = new DisassembleCommand(offset, null, true);
			dism.applyTo(program, TaskMonitor.DUMMY);
			
			fpa.addEntryPoint(offset);
			fpa.createFunction(offset, xdef.getName());
		}
		
		for (XrefSymbol xref : xrefs.values()) {
			Address offset = fpa.toAddr(xref.getAddress());
			try {
				symTbl.createLabel(offset, xref.getName(), SourceType.IMPORTED);
			} catch (Exception e) {
				log.appendException(e);
				return;
			}
		}
		
		for (LocalSymbol local : locals) {
			Address offset = fpa.toAddr(local.getAddress());
			try {
				symTbl.createLabel(offset, local.getName(), SourceType.IMPORTED);
			} catch (Exception e) {
				log.appendException(e);
				return;
			}
		}
		
		for (LocalSymbol vlocal : vlocals) {
			Address offset = fpa.toAddr(vlocal.getAddress());
			try {
				symTbl.createLabel(offset, vlocal.getName(), SourceType.IMPORTED);
			} catch (Exception e) {
				log.appendException(e);
				return;
			}
		}
		
		for (List<XbssSymbol> xbss_ : xbssList.values()) {
			for (XbssSymbol xbss : xbss_) {
				Address offset = fpa.toAddr(xbss.getAddress());
				try {
					symTbl.createLabel(offset, xbss.getName(), SourceType.IMPORTED);
					
					CreateArrayCmd array = new CreateArrayCmd(offset, (int) xbss.getLength(), ByteDataType.dataType, 1);
					array.applyTo(program);
				} catch (InvalidInputException e) {
					log.appendException(e);
					return;
				}
			}
		}

		Memory mem = program.getMemory();
		
		for (PatchInfo patch : patches) {
			int sectionIndex = patch.getSectionIndex();
			Section sect = sections.get(sectionIndex);
			byte[] sectionBytes = sect.getBytes();

			Address addr = fpa.toAddr(sect.getAddress() + patch.getOffset());
			long newAddr = patch.calcReference(symbols);
			byte[] newBytes = new byte[0];
			
			if (patch.getType() != 0x10) {
				Assembler asm = Assemblers.getAssembler(program);
				
				DisassembleCommand dism = new DisassembleCommand(addr, null, true);
				dism.applyTo(program, TaskMonitor.DUMMY);

				Instruction instr = listing.getInstructionAt(addr);
				String line = instr.toString().replace("_", "");
				// System.out.print(String.format("%s[%X]: %s -> ", sect.getName(), patch.getOffset(), line));
				
				String newLine = "";
				
				try {
					switch (patch.getType()) {
					case 'R': { // relative hi half
						long val = (newAddr >= 0) ? (newAddr >> 16) & 0xFFFF : 0;
						newLine = line.replaceFirst("-?0x[0-9A-Fa-f]+", String.format("%s0x%X", val < 0 ? "-" : "", val < 0 ? (-(val & 0xFFFF)) & 0xFFFF:val));
					} break;
					case 'T': { // relative lo half
						long val = (short)(newAddr >> 0);
						newLine = line.replaceFirst("-?0x[0-9A-Fa-f]+", String.format("%s0x%X", val < 0 ? "-" : "", val < 0 ? (-(val & 0xFFFF)) & 0xFFFF:val));
					} break;
					case 'J': { // jump
						newLine = line.replaceFirst("0x[0-9A-Fa-f]+", String.format("0x%08X", newAddr));
					} break;
					case 0x1E: { // relative to fp register
						newLine = line.replaceFirst("0x[0-9A-Fa-f]+", String.format("0x%X", newAddr));
					} break;
					case 0x64: { // relative to gp register
						newLine = line.replaceFirst("0x[0-9A-Fa-f]+", String.format("0x%X", newAddr));
					} break;
					default: {
						log.appendException(new Exception(String.format("Unknown patch tag 0x%02X", patch.getType())));
						return;
					}
					}
					
					newBytes = asm.assembleLine(addr, newLine);
					System.arraycopy(newBytes, 0, sectionBytes, patch.getOffset(), newBytes.length);
				} catch (AssemblySyntaxException | AssemblySemanticException e) {
					log.appendException(e);
					return;
				}
				
				try {
					asm.patchProgram(newBytes, addr);
					
				} catch (MemoryAccessException e) {
					log.appendException(e);
					return;
				}
			} else {
				newBytes = intToBytes((int)newAddr);
				System.arraycopy(newBytes, 0, sectionBytes, patch.getOffset(), newBytes.length);
				
				try {
					InstructionStasher instructionStasher = new InstructionStasher(program, addr);
					mem.setBytes(addr, newBytes);
					instructionStasher.restore();
					
				} catch (MemoryAccessException | CodeUnitInsertionException e) {
					log.appendException(e);
					return;
				}
			}
			
			sect.setBytes(sectionBytes);
			
			if (patch.isExternal()) {
				Symbol sym = symbols.get(patch.getExternalIndex());
				Address refAddr = fpa.toAddr(sym.getAddress());
				try {
					if ((sym instanceof XrefSymbol && !((XrefSymbol)sym).isXbssSymbol()) &&
							listing.isUndefined(refAddr, refAddr.add(PointerDataType.dataType.getLength()))) {
						fpa.createFunction(refAddr, sym.getName());
						listing.createData(refAddr, PointerDataType.dataType);
					}
				} catch (CodeUnitInsertionException e) {
					log.appendException(e);
					return;
				}
			}
		}
	}
	
	private static byte[] intToBytes(int x) {
	    ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
	    buffer.order(ByteOrder.LITTLE_ENDIAN);
	    buffer.putInt(x);
	    return buffer.array();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}
}

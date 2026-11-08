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

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(
		type = "psyqlibfile", // ([a-z0-9]+ only)
		description = "PsyQ Library File",
		factory = PsyqLibFileSystem.PsyqFileSystemFactory.class)
public class PsyqLibFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<LibFileItem> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public PsyqLibFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 */
	public void mount(TaskMonitor monitor) {
		monitor.setMessage("Opening " + PsyqLibFileSystem.class.getSimpleName() + "...");
		monitor.clearCancelled();
		
		BinaryReader reader = new BinaryReader(provider, true);

		try {
			byte libVer = reader.readByte(3);
			long startOffset = 4;
			
			switch (libVer) {
			case 1:
			{
				while (startOffset < reader.length()) {
					if (monitor.isCancelled()) {
						break;
					}
					
					reader.setPointerIndex(startOffset);			
					String name = reader.readNextAsciiString(8);
					long date = reader.readNextUnsignedInt();
					
					Date dateTime = convertDosDate(date);
					
					long offset = reader.readNextUnsignedInt();
					long size = reader.readNextUnsignedInt();
					
					LibFileItem item = new LibFileItem();
					item.name = name + ".OBJ";
					item.date = dateTime;
					item.offset = startOffset + offset;
					item.size = size - offset;
		
					fsih.storeFile(item.name, fsih.getFileCount(), false, item.size, item);
					
					startOffset += size;
				}
			} break;
			case 2:
			{
				reader.setPointerIndex(startOffset);
				
				long infoOff = reader.readNextUnsignedInt();
				long infoLen = reader.readNextUnsignedInt();
				
				reader.setPointerIndex(infoOff);
				
				while (infoLen > 0) {
					long dataOffset = reader.readNextUnsignedInt(); infoLen -= 4;
					long dataSize = reader.readNextUnsignedInt(); infoLen -= 4;
					long date = reader.readNextUnsignedInt(); infoLen -= 4;
					byte nameLen = reader.readNextByte(); infoLen -= 1;
					nameLen += 1;
					
					String name = reader.readNextAsciiString(nameLen); infoLen -= nameLen;
					
					byte itemsCount = reader.readNextByte(); infoLen -= 1;
					
					Date dateTime = convertDosDate(date);
					
					LibFileItem item = new LibFileItem();
					item.name = name;
					item.date = dateTime;
					item.offset = dataOffset;
					item.size = dataSize;
		
					fsih.storeFile(item.name, fsih.getFileCount(), false, item.size, item);
					
					while (itemsCount > 0) {
						reader.readNextUnsignedShort(); infoLen -= 2;
						byte nameLen2 = reader.readNextByte(); infoLen -= 1;
						nameLen2 += 1;
						
						reader.readNextAsciiString(nameLen2); infoLen -= nameLen2;
						
						itemsCount = reader.readNextByte(); infoLen -= 1;
					}
				}
			} break;
			}
		} catch (IOException e) {
			return;
		}
	}
	
	private static Date convertDosDate(long date) {
		int tt = (int) (date >> 16) & 0xFFFF;
		int dd = (int) (date >> 0) & 0xFFFF;
		
		int year = (dd >> 9) + 1980;
		int month = (dd >> 5) & 0xF;
		int day = dd & 0x1F;
		
		int hour = tt >> 11;
		int minute = (tt >> 5) & 0x3F;
		int second = (tt & 0x1F) << 1;
	    
	    Calendar cl = Calendar.getInstance();
	    cl.set(year, month, day, hour, minute, second);
	    
	    return cl.getTime();
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		LibFileItem metadata = fsih.getMetadata(file);
		return (metadata != null)
				? new ByteProviderWrapper(provider, metadata.offset, metadata.size, file.getFSRL())
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		LibFileItem metadata = fsih.getMetadata(file);
		FileAttributes result = new FileAttributes();
		if (metadata != null) {
			result.add(FileAttributeType.NAME_ATTR, metadata.name);
			result.add(FileAttributeType.SIZE_ATTR, metadata.size);
			result.add(FileAttributeType.CREATE_DATE_ATTR, metadata.date);
		}
		return result;
	}

	// TODO: Customize for the real file system.
	public static class PsyqFileSystemFactory
			implements GFileSystemFactoryByteProvider<PsyqLibFileSystem>, GFileSystemProbeByteProvider {

		@Override
		public PsyqLibFileSystem create(FSRLRoot targetFSRL,
				ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
						throws IOException, CancelledException {

			PsyqLibFileSystem fs = new PsyqLibFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}

		@Override
		public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			byte[] tag = byteProvider.readBytes(0, 4);
			return Arrays.equals(tag, new byte[] {0x4C, 0x49, 0x42, 0x01}) || Arrays.equals(tag, new byte[] {0x4C, 0x49, 0x42, 0x02}); // LIB\x02
		}
	}

	private static class LibFileItem {
		private String name;
		private Date date;
		private long offset;
		private long size;
	}
}

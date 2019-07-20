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
package psxpsyq;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(
		type = "psxpsyqlibfile", // ([a-z0-9]+ only)
		description = "PsyQ Library File",
		factory = PsxPsyqLibFileSystem.PsxPsyqFileSystemFactory.class)
public class PsxPsyqLibFileSystem implements GFileSystem {

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
	public PsxPsyqLibFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
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
		monitor.setMessage("Opening " + PsxPsyqLibFileSystem.class.getSimpleName() + "...");
		
		BinaryReader reader = new BinaryReader(provider, true);
		long startOffset = 4;

		try {
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
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		LibFileItem metadata = fsih.getMetadata(file);
		return (metadata != null)
				? new ByteProviderInputStream(provider, metadata.offset, metadata.size)
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) throws IOException {
		LibFileItem metadata = fsih.getMetadata(file);
		return (metadata == null) ? null : FSUtilities.infoMapToString(getInfoMap(metadata));
	}

	public Map<String, String> getInfoMap(LibFileItem metadata) {
		Map<String, String> info = new LinkedHashMap<>();
		info.put("Name", metadata.name);
		info.put("Size", "0x" + Long.toHexString(metadata.size));
		info.put("Date", (new SimpleDateFormat("dd-MM-yy HH:mm:ss")).format(metadata.date));
		return info;
	}

	// TODO: Customize for the real file system.
	public static class PsxPsyqFileSystemFactory
			implements GFileSystemFactoryFull<PsxPsyqLibFileSystem>, GFileSystemProbeFull {

		@Override
		public PsxPsyqLibFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
				ByteProvider byteProvider, File containerFile, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			PsxPsyqLibFileSystem fs = new PsxPsyqLibFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}

		@Override
		public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
				FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			byte[] tag = byteProvider.readBytes(0, 4);
			return Arrays.equals(tag, new byte[] {0x4C, 0x49, 0x42, 0x01});
		}
	}

	private static class LibFileItem {
		private String name;
		private Date date;
		private long offset;
		private long size;
	}
}

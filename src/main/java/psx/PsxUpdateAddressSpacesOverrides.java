package psx;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.util.ObjectStorage;
import ghidra.util.PrivateSaveable;

public class PsxUpdateAddressSpacesOverrides extends PrivateSaveable {
	
	public static long ADDRESS = 0x10000000;
	
	private Class<?>[] fields = new Class<?>[] {
		byte[].class
	};
	
	private List<PsxUpdateAddressSpacesOverride> overrides;

	public PsxUpdateAddressSpacesOverrides(ArrayList<PsxUpdateAddressSpacesOverride> overrides) {
		this.overrides = overrides;
	}
	
	public PsxUpdateAddressSpacesOverrides() {
		overrides = new ArrayList<>();
	}
	
	public Iterator<PsxUpdateAddressSpacesOverride> getOverridesIterator() {
		return overrides.iterator();
	}
	
	public void mergeOverrides(final List<PsxUpdateAddressSpacesOverride> newOverrides) {
		overrides.addAll(newOverrides);
	}
	
	@Override
	public Class<?>[] getObjectStorageFields() {
		return fields;
	}

	@Override
	public void save(ObjectStorage objStorage) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		
		try  {
			ObjectOutputStream objStream = new ObjectOutputStream(stream);

			int size = overrides.size();
			objStream.writeInt(size);
			
			for (int i = 0; i < size; ++i) {
				objStream.writeObject(overrides.get(i).getFunctionAddress().toString());
				objStream.writeInt(overrides.get(i).getLineNumber());
				objStream.writeObject(overrides.get(i).getSymbolAddress().toString());
			}
			
			objStream.flush();
			
			objStorage.putBytes(stream.toByteArray());
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
			}
		}
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		overrides.clear();
		
		ByteArrayInputStream stream = new ByteArrayInputStream(objStorage.getBytes());
		
		try {
			ObjectInputStream objStream = new ObjectInputStream(stream);
			int size = objStream.readInt();
			
			for (int i = 0; i < size; ++i) {
				String funcAddr = (String) objStream.readObject();
				int lineNum = objStream.readInt();
				String symAddr = (String) objStream.readObject();
				
				overrides.add(new PsxUpdateAddressSpacesOverride(funcAddr, lineNum, symAddr));
			}
			
			objStream.close();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
			}
		}
	}

	@Override
	public int getSchemaVersion() {
		return 0;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		

		return overrides.equals(((PsxUpdateAddressSpacesOverrides)obj).overrides);
	}
}

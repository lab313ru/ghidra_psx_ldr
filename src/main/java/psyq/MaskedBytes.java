package psyq;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import generic.stl.Pair;

public class MaskedBytes {

	private byte[] bytes;
	private byte[] masks;

	public byte[] getBytes() {
		return bytes;
	}

	public byte[] getMasks() {
		return masks;
	}
	
	public int getLength() {
		return bytes.length;
	}

	public MaskedBytes(final byte[] bytes, final byte[] masks) {
		this.bytes = bytes;
		this.masks = masks;
	}
	
	public List<Pair<String, Integer>> applyPatches(final List<Pair<Integer, Pair<String, String>>> patches, final List<Pair<String, Integer>> labels) throws IOException {
		if (patches == null || patches.isEmpty()) {
			return labels;
		}
		
		List<Pair<String, Integer>> newLabels = new ArrayList<>();
		newLabels.addAll(labels);
		
		int offsetDelta = 0;
		
		for (var patch : patches) {
			final int patchOff = offsetDelta + patch.first;
			final Pair<String, String> patchData = patch.second;
			final MaskedBytes patchBytes = fromMaskedString(patchData.first.substring(1));
			final MaskedBytes patchCheckBytes = fromMaskedString(patchData.second);
			final byte[] checkBytes = (patchCheckBytes != null) ? patchCheckBytes.getBytes() : null;
			final long patchBytesLen = (patchBytes != null) ? patchBytes.getLength() : 0L;
			long shift = 0L;
			
			switch (patchData.first.charAt(0)) {
			case '~': { // replace bytes
				for (int i = 0; i < patchBytesLen; ++i) {
					if (bytes[patchOff + i] != checkBytes[i]) {
						throw new IOException(String.format("Wrong replace-patch data, OFF: %d, data: %s", patch.first, patchData.second));
					}
					
					bytes[patchOff + i] = patchBytes.bytes[i];
					masks[patchOff + i] = patchBytes.masks[i];
				}
			} break;
			case '+': { // insert bytes
				final MaskedBytes newData = expand(new MaskedBytes(bytes, masks), patchBytes, patchOff);
				this.bytes = newData.getBytes();
				this.masks = newData.getMasks();
				
				shift = patchBytesLen;
				offsetDelta += patchBytesLen;
			} break;
			case '-': { // remove bytes
				final int count = Integer.parseInt(patchData.first.substring(1));
				final MaskedBytes newData = shrink(new MaskedBytes(bytes, masks), count, patchOff);
				this.bytes = newData.getBytes();
				this.masks = newData.getMasks();
				
				shift = -count;
				offsetDelta -= count;
			} break;
			}
			
			if (shift == 0L) {
				continue;
			}
			
			for (int i = 0; i < labels.size(); ++i) {
				final String lbName = labels.get(i).first;
				int lbOffset = newLabels.get(i).second;
				
				if (patchOff < lbOffset) {
					lbOffset += shift;
				}
				
				newLabels.set(i, new Pair<>(lbName, lbOffset));
			}
		}
		
		return newLabels;
	}
	
	private static MaskedBytes expand(final MaskedBytes src, final MaskedBytes add, int offset) {
		ByteArrayOutputStream newBytes = new ByteArrayOutputStream();
		ByteArrayOutputStream newMasks = new ByteArrayOutputStream();
		
		try {
			newBytes.write(Arrays.copyOf(src.getBytes(), offset));
			newMasks.write(Arrays.copyOf(src.getMasks(), offset));
			
			newBytes.write(add.getBytes());
			newMasks.write(add.getMasks());
			
			newBytes.write(Arrays.copyOfRange(src.getBytes(), offset, src.getLength()));
			newMasks.write(Arrays.copyOfRange(src.getMasks(), offset, src.getLength()));
			
			return new MaskedBytes(newBytes.toByteArray(), newMasks.toByteArray());
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private static MaskedBytes shrink(final MaskedBytes src, int length, int offset) {
		ByteArrayOutputStream newBytes = new ByteArrayOutputStream();
		ByteArrayOutputStream newMasks = new ByteArrayOutputStream();
		
		try {
			newBytes.write(Arrays.copyOf(src.getBytes(), offset));
			newMasks.write(Arrays.copyOf(src.getMasks(), offset));
			
			newBytes.write(Arrays.copyOfRange(src.getBytes(), offset + length, src.getLength()));
			newMasks.write(Arrays.copyOfRange(src.getMasks(), offset + length, src.getLength()));
			
			return new MaskedBytes(newBytes.toByteArray(), newMasks.toByteArray());
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static MaskedBytes fromMaskedString(final String sig) {
		if (sig == null) {
			return null;
		}
		
		int len = sig.length();
		
		if ((len % 3) != 0) {
			return null;
		}
		
	    byte[] bytes = new byte[len / 3];
	    byte[] masks = new byte[len / 3];
	    
	    for (int i = 0; i < len; i += 3) {
	    	char c1 = sig.charAt(i);
	    	char c2 = sig.charAt(i + 1);
	    	
	    	masks[i / 3] = (byte) (
	    			(((c1 == '?') ? 0x0 : 0xF) << 4) |
	    			(((c2 == '?') ? 0x0 : 0xF))
	    			);
	    	bytes[i / 3] = (byte) (
	    			(((c1 == '?') ? 0x0 : Character.digit(c1, 16)) << 4) |
	    			(((c2 == '?') ? 0x0 : Character.digit(c2, 16)))
	    			);
	    }
	    
	    return new MaskedBytes(bytes, masks);
	}
}

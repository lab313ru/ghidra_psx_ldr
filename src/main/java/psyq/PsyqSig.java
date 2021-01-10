package psyq;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public final class PsyqSig {
	private final String name;
	private final MaskedBytes sig;
	private final Map<String, Long> labels;
	private boolean applied = false;
	private final float entropy;
	
	private PsyqSig(final String name, final MaskedBytes sig, final Map<String, Long> labels) {
		this.name = name;
		this.sig = sig;
		this.labels = labels;
		this.entropy = calcEntropy(sig);
	}
	
	public float getEntropy() {
		return entropy;
	}
	
	public void setApplied(boolean applied) {
		this.applied = applied;
	}
	
	public boolean isApplied() {
		return applied;
	}
	
	public String getName() {
		return name;
	}

	public MaskedBytes getSig() {
		return sig;
	}

	public Map<String, Long> getLabels() {
		return labels;
	}
	
	public static PsyqSig fromJsonToken(final JsonObject token) {
		final String name = token.get("name").getAsString();
		final String sig = token.get("sig").getAsString();
		final MaskedBytes signature = fromMaskedString(sig);
		
		final Map<String, Long> labels = new HashMap<>();
		
		final JsonArray arr = token.get("labels").getAsJsonArray();
		
		for (var item : arr) {
			final JsonObject itemObj = item.getAsJsonObject();
			
			final String itemName = itemObj.get("name").getAsString();
			final long itemOffset = itemObj.get("offset").getAsLong();
			labels.put(itemName, itemOffset);
		}
		
		return new PsyqSig(name, signature, labels);
	}
	
	private static MaskedBytes fromMaskedString(final String sig) {
		int len = sig.length();
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
	
    private static float calcEntropy(final MaskedBytes bytes) {
        int counts[] = new int[256];
        float entropy = 0;
        float total = bytes.getLength();
        
        byte[] f = bytes.getBytes();
        byte[] m = bytes.getMasks();
        
        for (int i = 0; i < m.length; ++i) {
        	f[i] &= m[i];
        }

        for (byte b : f)
            counts[b + 128]++;
        for (int c : counts) {
            if (c == 0)
                continue;
            float p = c / total;

            entropy -= p * Math.log(p) / Math.log(2);
        }

        return entropy;
    }
}

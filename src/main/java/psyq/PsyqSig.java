package psyq;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import generic.stl.Pair;

public final class PsyqSig {
	private final String name;
	private final MaskedBytes sig;
	private final List<Pair<String, Integer>> labels;
	private boolean applied = false;
	private final float entropy;
	
	private PsyqSig(final String name, final MaskedBytes sig, final List<Pair<String, Integer>> labels) {
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

	public List<Pair<String, Integer>> getLabels() {
		return labels;
	}
	
	public static PsyqSig fromJsonToken(final JsonObject token, final JsonArray patches) throws IOException {
		final String name = token.get("name").getAsString();
		final String sig = token.get("sig").getAsString();
		
		final MaskedBytes signature = MaskedBytes.fromMaskedString(sig);
		
		final List<Pair<String, Integer>> labels = new ArrayList<>();
		final JsonArray arr = token.get("labels").getAsJsonArray();
		
		for (var item : arr) {
			final JsonObject itemObj = item.getAsJsonObject();
			
			final String itemName = itemObj.get("name").getAsString();
			final int itemOffset = itemObj.get("offset").getAsInt();
			labels.add(new Pair<>(itemName, itemOffset));
		}
		
		if (patches == null) {
			return new PsyqSig(name, signature, labels);
		}
		
		final List<Pair<Integer, Pair<String, String>>> patchesList = new ArrayList<>();
		
		for (var patch : patches) {
			final JsonObject itemObj = patch.getAsJsonObject();
			
			final String patchObjName = itemObj.get("name").getAsString();
			
			if (!name.equalsIgnoreCase(patchObjName)) {
				continue;
			}
			
			final JsonArray posPatches = itemObj.getAsJsonArray("patches");
			
			for (var posPatch : posPatches) {
				final JsonObject posPatchObj = posPatch.getAsJsonObject();
				
				final int itemPos = posPatchObj.get("pos").getAsInt();
				final String itemData = posPatchObj.get("data").getAsString();
				final String itemCheckData = posPatchObj.has("check") ? posPatchObj.get("check").getAsString() : null;
				patchesList.add(new Pair<>(itemPos, new Pair<>(itemData, itemCheckData)));
			}
		}
		
		try {
			final List<Pair<String, Integer>> newLabels = signature.applyPatches(patchesList, labels);
			return new PsyqSig(name, signature, newLabels);
		} catch (IOException e) {
			throw new IOException(String.format("OBJ: %s, %s", name, e.getMessage()));
		}
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

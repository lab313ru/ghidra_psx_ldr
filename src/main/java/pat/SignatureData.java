package pat;

import java.util.Arrays;
import java.util.List;

public class SignatureData {
	private final MaskedBytes templateBytes, tailBytes;
	private MaskedBytes fullBytes;
	private final int crc16Length;
	private final short crc16;
	private final int moduleLength;
	private final List<ModuleData> modules;
	
	public SignatureData(MaskedBytes templateBytes, int crc16Length,
			short crc16, int moduleLength, List<ModuleData> modules, MaskedBytes tailBytes) {
		this.templateBytes = this.fullBytes = templateBytes;
		this.crc16Length = crc16Length;
		this.crc16 = crc16;
		this.moduleLength = moduleLength;
		this.modules = modules;
		this.tailBytes = tailBytes;
		
		if (this.tailBytes != null) {
			int addLength = moduleLength - templateBytes.getLength() - tailBytes.getLength();
			
			byte[] addBytes = new byte[addLength];
			byte[] addMasks = new byte[addLength];
			Arrays.fill(addBytes, (byte)0x00);
			Arrays.fill(addMasks, (byte)0x00);
			
			this.fullBytes = MaskedBytes.extend(this.templateBytes, addBytes, addMasks);
			this.fullBytes = MaskedBytes.extend(this.fullBytes, tailBytes);
		}
	}

	public MaskedBytes getTemplateBytes() {
		return templateBytes;
	}

	public MaskedBytes getTailBytes() {
		return tailBytes;
	}
	
	public MaskedBytes getFullBytes() {
		return fullBytes;
	}

	public int getCrc16Length() {
		return crc16Length;
	}

	public short getCrc16() {
		return crc16;
	}

	public int getModuleLength() {
		return moduleLength;
	}

	public List<ModuleData> getModules() {
		return modules;
	}
}

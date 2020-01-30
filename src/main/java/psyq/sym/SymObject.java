package psyq.sym;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

public class SymObject implements ISymObject {
	protected final long offset;
	protected final long overlayId;
	
	protected SymObject(long offset, long overlayId) {
		this.offset = offset;
		this.overlayId = overlayId;
	}

	@Override
	public long getOffset() {
		return offset;
	}
	
	@Override
	public long getOverlayId() {
		return overlayId;
	}
	
	public Address getAddress(Program program) {
		AddressFactory addrFact = program.getAddressFactory();
		AddressSpace addrSpace = addrFact.getAddressSpace(SymOverlay.getBlockName(overlayId));
		
		if (addrSpace == null) {
			addrSpace = addrFact.getDefaultAddressSpace();
		}
		
		return addrSpace.getAddress(offset);
	}
}

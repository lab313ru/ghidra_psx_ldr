# Takes all references to address and points them to same address in main memory
#@author markisha64 <marko.grizelj03@gmail.com>
#@category Reference
#@keybinding
#@menupath Tools.References.Reference Main
#@toolbar

from ghidra.program.flatapi import FlatProgramAPI

api = FlatProgramAPI(currentProgram)
addFact = api.getAddressFactory()

refs = currentProgram.referenceManager.getReferencesTo(currentAddress)

for ref in refs:
	instruction = api.getInstructionAt(ref.getFromAddress())

	if not instruction:
		continue

	operand = ref.getOperandIndex()
	address = addFact.getAddress(ref.getToAddress().toString("ram:"))
	refType = ref.getReferenceType()

	newRef = api.createMemoryReference(instruction, operand, address, refType)
	api.setReferencePrimary(newRef)

	api.removeReference(ref)


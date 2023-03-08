package psyq;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;

public class LibgpuMacroDetector {

	static private void SetComment(PcodeOpAST value, String comment, CodeManager codeManager) {
		Address address = value.getSeqnum().getTarget();
		codeManager.setComment(address, CodeUnit.PRE_COMMENT, comment);
	}

	static public void detectLibgpuMacros(Program program, final Address startAddr, final Address endAddr,
			TaskMonitor monitor) throws Exception {
		Map<Integer, String> primCodeMap = new HashMap<Integer, String>() {
			{
				put(0x20, "setPolyF3()");
				put(0x22, "setPolyF3() + setSemiTrans(polyF3, 1)");

				put(0x24, "setPolyFT3()");
				put(0x26, "setPolyFT3() + setSemiTrans(polyFT3, 1)");
				put(0x25, "setPolyFT3() + setShadeTex(polyFT3, 1)");
				put(0x27, "setPolyFT3() + setSemiTrans(polyFT3, 1) + setShadeTex(polyFT3, 1");

				put(0x30, "setPolyG3()");
				put(0x32, "setPolyG3() + setSemiTrans(polyG3, 1)");

				put(0x34, "setPolyGT3()");
				put(0x36, "setPolyGT3() + setSemiTrans(polyGT3, 1)");

				put(0x28, "setPolyF4()");
				put(0x2a, "setPolyF4() + setSemiTrans(polyF4, 1)");

				put(0x2c, "setPolyFT4()");
				put(0x2e, "setPolyFT4() + setSemiTrans(polyFT4, 1)");
				put(0x2d, "setPolyFT4() + setShadeTex(polyFT4, 1)");
				put(0x2f, "setPolyFT4() + setSemiTrans(polyFT4, 1) + setShadeTex(polyFT4, 1)");

				put(0x38, "setPolyG4()");
				put(0x3a, "setPolyG4() + setSemiTrans(polyG4, 1)");

				put(0x3c, "setPolyGT4()");
				put(0x3e, "setPolyGT4() + setSemiTrans(polyGT4, 1)");

				put(0x40, "setLineF2()");
				put(0x42, "setLineF2() + setSemiTrans(lineF2, 1)");

				put(0x50, "setLineG2()");
				put(0x52, "setLineG2() + setSemiTrans(lineG2, 1)");

				put(0x48, "setLineF3()");
				put(0x4a, "setLineF3() + setSemiTrans(lineF3, 1)");

				put(0x58, "setLineG3()");
				put(0x5a, "setLineG3() + setSemiTrans(lineG3, 1)");

				put(0x4c, "setLineF4()");
				put(0x4e, "setLineF4() + setSemiTrans(lineF4, 1)");

				put(0x5c, "setLineG4()");
				put(0x5e, "setLineG4() + setSemiTrans(lineG4, 1)");

				put(0x64, "setSprt()");
				put(0x66, "setSprt() + setSemiTrans(sprt, 1)");
				put(0x65, "setSprt() + setShadeTex(sprt, 1)");
				put(0x67, "setSprt() + setSemiTrans(sprt, 1) + setShadeTex(sprt, 1)");

				put(0x7c, "setSprt16()");
				put(0x7e, "setSprt16() + setSemiTrans(sprt16, 1)");
				put(0x7d, "setSprt16() + setShadeTex(sprt16, 1)");
				put(0x7f, "setSprt16() + setSemiTrans(sprt16, 1) + setShadeTex(sprt16, 1)");

				put(0x74, "setSprt8()");
				put(0x76, "setSprt8() + setSemiTrans(sprt8, 1)");
				put(0x75, "setSprt8() + setShadeTex(sprt8, 1)");
				put(0x77, "setSprt8() + setSemiTrans(sprt8, 1) + setShadeTex(sprt8, 1)");

				put(0x68, "setTile1()");
				put(0x6a, "setTile1() + setSemiTrans(tile1, 1)");

				put(0x78, "setTile8()");
				put(0x7a, "setTile8() + setSemiTrans(tile8, 1)");

				put(0x70, "setTile16()");
				put(0x72, "setTile16() + setSemiTrans(tile16, 1)");

				put(0x60, "setTile()");
				put(0x62, "setTile() + setSemiTrans(tile, 1)");
			}
		};

		CodeManager codeManager = ((ProgramDB) program).getCodeManager();
		FunctionManager functionManager = program.getFunctionManager();
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
		if (!ifc.openProgram(program)) {
			throw new DecompileException("Fatal error", "The decompiler was unable to open the program.");
		}

		ArrayList<String> logLines = new ArrayList<String>();

		for (Function function : functionManager.getFunctions(startAddr, true)) {
			if (monitor.isCancelled() || function.getEntryPoint().getOffset() > endAddr.getOffset()) {
				break;
			}

			// sprintf() triggers a huge amount of false positives for setPolyG3().
			String functionName = function.getName();
			if (functionName.contains("sprintf") || functionName.contains("SPRINTF")) {
				continue;
			}

			DecompileResults decompResults = ifc.decompileFunction(function, 30, null);
			HighFunction highFunction = decompResults.getHighFunction();
			Iterator<PcodeOpAST> ast = highFunction.getPcodeOps();
			ArrayList<PcodeOpAST> PcodeOps = new ArrayList<PcodeOpAST>();
			while (ast.hasNext()) {
				PcodeOps.add(ast.next());
			}

			for (int i = 0; i < PcodeOps.size(); i++) {

				PcodeOpAST value = PcodeOps.get(i);
				int opCode = value.getOpcode();

				/*
				 * Detect primitive initializers.
				 */
				if (opCode == PcodeOp.INT_ADD) {

					long offset = value.getInput(1).getOffset();
					// The primitive code is at a 7-byte offset but compiler optimization of
					// primitive initialization in loops leads to a variety of odd offsets being
					// used.
					if (offset % 2 == 1) {
						// Sometimes the ADD and STORE used to initialize a primitive are several
						// instructions apart.
						// Note that the iteration count is based on testing on the Metal Gear Solid
						// binary and may not be optimal for other games.
						for (int j = i + 1; j < i + 8; j++) {

							if (j < PcodeOps.size()) {

								value = PcodeOps.get(j);
								if (value.getOpcode() == PcodeOp.STORE
										&& value.getInput(2).isConstant()) {

									long primCode = value.getInput(2).getOffset();
									if (primCodeMap.containsKey((int) primCode)) {

										String confidence = (offset == 7) ? "Probable" : "Possible";
										String macro = primCodeMap.get((int) primCode);
										SetComment(value, confidence + " PsyQ macro: " + macro, codeManager);
										logLines.add(value.getSeqnum().getTarget().toString() + ": " + macro);
									}
									break;
								}
							}
						}
					}
					
					/*
					 * Detect addPrim() and nextPrim().
					 */
				} else if (opCode == PcodeOp.INT_AND
						&& value.getInput(0).isRegister()) {

					long offset = value.getInput(1).getOffset();
					long register1 = value.getInput(0).getOffset();
					if (i + 1 < PcodeOps.size()) {

						value = PcodeOps.get(i + 1);
						if (offset == 0xff000000L
								&& value.getOpcode() == PcodeOp.INT_AND
								&& value.getInput(0).isRegister()
								&& value.getInput(1).getOffset() == 0xffffff) {

							long register2 = value.getInput(0).getOffset();
							value = PcodeOps.get(i + 2);
							if (value.getOpcode() == PcodeOp.INT_OR
									&& value.getInput(0).getOffset() == register1
									&& value.getInput(1).getOffset() == register2) {

								SetComment(value, "Probable PsyQ macro: addPrim().", codeManager);
								logLines.add(value.getSeqnum().getTarget().toString() + ": addPrim()");
							}
						} else if (offset == 0xffffffL
								&& value.getOpcode() == PcodeOp.INT_OR
								&& value.getInput(0).isRegister()
								&& value.getInput(0).getOffset() == register1
								&& value.getInput(1).getOffset() == 0x80000000L) {

							SetComment(value,
									"Probable PsyQ macro: nextPrim(), with pattern: *pPrim & 0xffffff | 0x80000000.",
									codeManager);
							logLines.add(value.getSeqnum().getTarget().toString() + ": nextPrim()");
						}
					}
					
					/*
					 * Detect get/setClut().
					 */
				} else if (opCode == PcodeOp.INT_RIGHT
						&& value.getInput(1).getOffset() == 0x4) {

					// Sometimes there is a CAST between the right shift and the bitwise and.
					value = (PcodeOps.get(i + 1).getOpcode() == PcodeOp.CAST) ? PcodeOps.get(i + 2)
							: PcodeOps.get(i + 1);

					if (value.getOpcode() == PcodeOp.INT_AND
							&& value.getInput(1).getOffset() == 0x3f) {

						SetComment(value, "Probable PsyQ macro: get/setClut(), with pattern: y << 6 | x >> 4 & 0x3f.",
								codeManager);
						logLines.add(value.getSeqnum().getTarget().toString() + ": get/setClut()");
					}
					
					/*
					 * Detect setDrawTPage().
					 */
				} else if ((opCode == PcodeOp.STORE && (value.getInput(2).getOffset() & 0xfffff000) == 0xe1000000L)
						|| (opCode == PcodeOp.INT_OR && (value.getInput(1).getOffset() & 0xfffff000) == 0xe1000000L)) {

					SetComment(value,
							"Probable PsyQ macro: setDrawTPage() if setlen(p, 1), setDrawMode() if setlen(p, 2).",
							codeManager);
					logLines.add(value.getSeqnum().getTarget().toString() + ": setDrawTPage() or setDrawMode()");
				}
			}
		}

		// Path log = Paths.get("log.txt");
		// Files.write(log, logLines, StandardCharsets.UTF_8);
	}
}
